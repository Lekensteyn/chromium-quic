// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_THIRD_PARTY_QUIC_TOOLS_QUIC_MEMORY_CACHE_BACKEND_H_
#define NET_THIRD_PARTY_QUIC_TOOLS_QUIC_MEMORY_CACHE_BACKEND_H_

#include <list>
#include <map>
#include <memory>
#include <vector>

#include "net/third_party/quic/core/http/spdy_utils.h"
#include "net/third_party/quic/platform/api/quic_containers.h"
#include "net/third_party/quic/platform/api/quic_mutex.h"
#include "net/third_party/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quic/tools/quic_backend_response.h"
#include "net/third_party/quic/tools/quic_simple_server_backend.h"
#include "net/third_party/quic/tools/quic_url.h"
#include "net/third_party/spdy/core/spdy_framer.h"

namespace quic {

// In-memory cache for HTTP responses.
// Reads from disk cache generated by:
// `wget -p --save_headers <url>`
class QuicMemoryCacheBackend : public QuicSimpleServerBackend {
 public:
  // Class to manage loading a resource file into memory.  There are
  // two uses: called by InitializeBackend to load resources
  // from files, and recursively called when said resources specify
  // server push associations.
  class ResourceFile {
   public:
    explicit ResourceFile(const QuicString& file_name);
    ResourceFile(const ResourceFile&) = delete;
    ResourceFile& operator=(const ResourceFile&) = delete;
    virtual ~ResourceFile();

    void Read();

    // |base| is |file_name_| with |cache_directory| prefix stripped.
    void SetHostPathFromBase(QuicStringPiece base);

    const QuicString& file_name() { return file_name_; }

    QuicStringPiece host() { return host_; }

    QuicStringPiece path() { return path_; }

    const spdy::SpdyHeaderBlock& spdy_headers() { return spdy_headers_; }

    QuicStringPiece body() { return body_; }

    const std::vector<QuicStringPiece>& push_urls() { return push_urls_; }

   protected:
    void HandleXOriginalUrl();
    void HandlePushUrls(const std::vector<QuicStringPiece>& push_urls);
    QuicStringPiece RemoveScheme(QuicStringPiece url);

    QuicString file_name_;
    QuicString file_contents_;
    QuicStringPiece body_;
    spdy::SpdyHeaderBlock spdy_headers_;
    QuicStringPiece x_original_url_;
    std::vector<QuicStringPiece> push_urls_;

   private:
    QuicStringPiece host_;
    QuicStringPiece path_;
    QuicMemoryCacheBackend* cache_;
  };

  QuicMemoryCacheBackend();
  QuicMemoryCacheBackend(const QuicMemoryCacheBackend&) = delete;
  QuicMemoryCacheBackend& operator=(const QuicMemoryCacheBackend&) = delete;
  ~QuicMemoryCacheBackend() override;

  // Retrieve a response from this cache for a given host and path..
  // If no appropriate response exists, nullptr is returned.
  const QuicBackendResponse* GetResponse(QuicStringPiece host,
                                         QuicStringPiece path) const;

  // Adds a simple response to the cache.  The response headers will
  // only contain the "content-length" header with the length of |body|.
  void AddSimpleResponse(QuicStringPiece host,
                         QuicStringPiece path,
                         int response_code,
                         QuicStringPiece body);

  // Add a simple response to the cache as AddSimpleResponse() does, and add
  // some server push resources(resource path, corresponding response status and
  // path) associated with it.
  // Push resource implicitly come from the same host.
  void AddSimpleResponseWithServerPushResources(
      QuicStringPiece host,
      QuicStringPiece path,
      int response_code,
      QuicStringPiece body,
      std::list<QuicBackendResponse::ServerPushInfo> push_resources);

  // Add a response to the cache.
  void AddResponse(QuicStringPiece host,
                   QuicStringPiece path,
                   spdy::SpdyHeaderBlock response_headers,
                   QuicStringPiece response_body);

  // Add a response, with trailers, to the cache.
  void AddResponse(QuicStringPiece host,
                   QuicStringPiece path,
                   spdy::SpdyHeaderBlock response_headers,
                   QuicStringPiece response_body,
                   spdy::SpdyHeaderBlock response_trailers);

  // Simulate a special behavior at a particular path.
  void AddSpecialResponse(
      QuicStringPiece host,
      QuicStringPiece path,
      QuicBackendResponse::SpecialResponseType response_type);

  void AddSpecialResponse(
      QuicStringPiece host,
      QuicStringPiece path,
      spdy::SpdyHeaderBlock response_headers,
      QuicStringPiece response_body,
      QuicBackendResponse::SpecialResponseType response_type);

  // Sets a default response in case of cache misses.  Takes ownership of
  // 'response'.
  void AddDefaultResponse(QuicBackendResponse* response);

  // |cache_cirectory| can be generated using `wget -p --save-headers <url>`.
  void InitializeFromDirectory(const QuicString& cache_directory);

  // Find all the server push resources associated with |request_url|.
  std::list<QuicBackendResponse::ServerPushInfo> GetServerPushResources(
      QuicString request_url);

  // Implements the functions for interface QuicSimpleServerBackend
  // |cache_cirectory| can be generated using `wget -p --save-headers <url>`.
  bool InitializeBackend(const QuicString& cache_directory) override;
  bool IsBackendInitialized() const override;
  void FetchResponseFromBackend(
      const spdy::SpdyHeaderBlock& request_headers,
      const QuicString& request_body,
      QuicSimpleServerBackend::RequestHandler* quic_server_stream) override;
  void CloseBackendResponseStream(
      QuicSimpleServerBackend::RequestHandler* quic_server_stream) override;

 private:
  void AddResponseImpl(QuicStringPiece host,
                       QuicStringPiece path,
                       QuicBackendResponse::SpecialResponseType response_type,
                       spdy::SpdyHeaderBlock response_headers,
                       QuicStringPiece response_body,
                       spdy::SpdyHeaderBlock response_trailers);

  QuicString GetKey(QuicStringPiece host, QuicStringPiece path) const;

  // Add some server push urls with given responses for specified
  // request if these push resources are not associated with this request yet.
  void MaybeAddServerPushResources(
      QuicStringPiece request_host,
      QuicStringPiece request_path,
      std::list<QuicBackendResponse::ServerPushInfo> push_resources);

  // Check if push resource(push_host/push_path) associated with given request
  // url already exists in server push map.
  bool PushResourceExistsInCache(QuicString original_request_url,
                                 QuicBackendResponse::ServerPushInfo resource);

  // Cached responses.
  QuicUnorderedMap<QuicString, std::unique_ptr<QuicBackendResponse>> responses_
      GUARDED_BY(response_mutex_);

  // The default response for cache misses, if set.
  std::unique_ptr<QuicBackendResponse> default_response_
      GUARDED_BY(response_mutex_);

  // A map from request URL to associated server push responses (if any).
  std::multimap<QuicString, QuicBackendResponse::ServerPushInfo>
      server_push_resources_ GUARDED_BY(response_mutex_);

  // Protects against concurrent access from test threads setting responses, and
  // server threads accessing those responses.
  mutable QuicMutex response_mutex_;
  bool cache_initialized_;
};

}  // namespace quic

#endif  // NET_THIRD_PARTY_QUIC_TOOLS_QUIC_MEMORY_CACHE_BACKEND_H_
