// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_HTTP_RESPONSE_CACHE_H_
#define NET_TOOLS_QUIC_QUIC_HTTP_RESPONSE_CACHE_H_

#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/http/http_response_headers.h"
#include "net/quic/core/spdy_utils.h"
#include "net/spdy/spdy_framer.h"
#include "url/gurl.h"

namespace net {

// In-memory cache for HTTP responses.
// Reads from disk cache generated by:
// `wget -p --save_headers <url>`
class QuicHttpResponseCache {
 public:
  // A ServerPushInfo contains path of the push request and everything needed in
  // comprising a response for the push request.
  struct ServerPushInfo {
    ServerPushInfo(GURL request_url,
                   SpdyHeaderBlock headers,
                   SpdyPriority priority,
                   std::string body);
    ServerPushInfo(const ServerPushInfo& other);
    GURL request_url;
    SpdyHeaderBlock headers;
    SpdyPriority priority;
    std::string body;
  };

  enum SpecialResponseType {
    REGULAR_RESPONSE,  // Send the headers and body like a server should.
    CLOSE_CONNECTION,  // Close the connection (sending the close packet).
    IGNORE_REQUEST,    // Do nothing, expect the client to time out.
  };

  // Container for response header/body pairs.
  class Response {
   public:
    Response();
    ~Response();

    SpecialResponseType response_type() const { return response_type_; }
    const SpdyHeaderBlock& headers() const { return headers_; }
    const SpdyHeaderBlock& trailers() const { return trailers_; }
    const base::StringPiece body() const { return base::StringPiece(body_); }

    void set_response_type(SpecialResponseType response_type) {
      response_type_ = response_type;
    }
    void set_headers(SpdyHeaderBlock headers) { headers_ = std::move(headers); }
    void set_trailers(SpdyHeaderBlock trailers) {
      trailers_ = std::move(trailers);
    }
    void set_body(base::StringPiece body) { body.CopyToString(&body_); }

   private:
    SpecialResponseType response_type_;
    SpdyHeaderBlock headers_;
    SpdyHeaderBlock trailers_;
    std::string body_;

    DISALLOW_COPY_AND_ASSIGN(Response);
  };

  // Class to manage loading a resource file into memory.  There are
  // two uses: called by InitializeFromDirectory to load resources
  // from files, and recursively called when said resources specify
  // server push associations.
  class ResourceFile {
   public:
    explicit ResourceFile(const base::FilePath& file_name);
    virtual ~ResourceFile();

    void Read();

    void SetHostPathFromBase(base::StringPiece base);

    base::StringPiece host() { return host_; }
    void set_host(base::StringPiece host) { host_ = host; }

    base::StringPiece path() { return path_; }
    void set_path(base::StringPiece path) { path_ = path; }

    const SpdyHeaderBlock& spdy_headers() { return spdy_headers_; }

    base::StringPiece body() { return body_; }

    const std::vector<base::StringPiece>& push_urls() { return push_urls_; }

    const std::string& file_name() { return file_name_string_; }

   protected:
    void HandleXOriginalUrl();
    void HandlePushUrls(const std::vector<base::StringPiece>& push_urls);
    base::StringPiece RemoveScheme(base::StringPiece url);

    const std::string cache_directory_;
    const base::FilePath file_name_;
    const std::string file_name_string_;
    std::string file_contents_;
    base::StringPiece body_;
    SpdyHeaderBlock spdy_headers_;
    base::StringPiece x_original_url_;
    std::vector<base::StringPiece> push_urls_;

   private:
    base::StringPiece host_;
    base::StringPiece path_;
    QuicHttpResponseCache* cache_;

    DISALLOW_COPY_AND_ASSIGN(ResourceFile);
  };

  QuicHttpResponseCache();
  ~QuicHttpResponseCache();

  // Retrieve a response from this cache for a given host and path..
  // If no appropriate response exists, nullptr is returned.
  const Response* GetResponse(base::StringPiece host,
                              base::StringPiece path) const;

  // Adds a simple response to the cache.  The response headers will
  // only contain the "content-length" header with the length of |body|.
  void AddSimpleResponse(base::StringPiece host,
                         base::StringPiece path,
                         int response_code,
                         base::StringPiece body);

  // Add a simple response to the cache as AddSimpleResponse() does, and add
  // some server push resources(resource path, corresponding response status and
  // path) associated with it.
  // Push resource implicitly come from the same host.
  void AddSimpleResponseWithServerPushResources(
      base::StringPiece host,
      base::StringPiece path,
      int response_code,
      base::StringPiece body,
      std::list<ServerPushInfo> push_resources);

  // Add a response to the cache.
  void AddResponse(base::StringPiece host,
                   base::StringPiece path,
                   SpdyHeaderBlock response_headers,
                   base::StringPiece response_body);

  // Add a response, with trailers, to the cache.
  void AddResponse(base::StringPiece host,
                   base::StringPiece path,
                   SpdyHeaderBlock response_headers,
                   base::StringPiece response_body,
                   SpdyHeaderBlock response_trailers);

  // Simulate a special behavior at a particular path.
  void AddSpecialResponse(base::StringPiece host,
                          base::StringPiece path,
                          SpecialResponseType response_type);

  // Sets a default response in case of cache misses.  Takes ownership of
  // 'response'.
  void AddDefaultResponse(Response* response);

  // |cache_cirectory| can be generated using `wget -p --save-headers <url>`.
  void InitializeFromDirectory(const std::string& cache_directory);

  // Find all the server push resources associated with |request_url|.
  std::list<ServerPushInfo> GetServerPushResources(std::string request_url);

 private:
  void AddResponseImpl(base::StringPiece host,
                       base::StringPiece path,
                       SpecialResponseType response_type,
                       SpdyHeaderBlock response_headers,
                       base::StringPiece response_body,
                       SpdyHeaderBlock response_trailers);

  std::string GetKey(base::StringPiece host, base::StringPiece path) const;

  // Add some server push urls with given responses for specified
  // request if these push resources are not associated with this request yet.
  void MaybeAddServerPushResources(base::StringPiece request_host,
                                   base::StringPiece request_path,
                                   std::list<ServerPushInfo> push_resources);

  // Check if push resource(push_host/push_path) associated with given request
  // url already exists in server push map.
  bool PushResourceExistsInCache(std::string original_request_url,
                                 ServerPushInfo resource);

  // Cached responses.
  std::unordered_map<std::string, std::unique_ptr<Response>> responses_;

  // The default response for cache misses, if set.
  std::unique_ptr<Response> default_response_;

  // A map from request URL to associated server push responses (if any).
  std::multimap<std::string, ServerPushInfo> server_push_resources_;

  // Protects against concurrent access from test threads setting responses, and
  // server threads accessing those responses.
  mutable base::Lock response_mutex_;

  DISALLOW_COPY_AND_ASSIGN(QuicHttpResponseCache);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_HTTP_RESPONSE_CACHE_H_
