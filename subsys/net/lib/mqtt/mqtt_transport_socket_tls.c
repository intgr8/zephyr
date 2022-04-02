/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file mqtt_transport_socket_tls.h
 *
 * @brief Internal functions to handle transport over TLS socket.
 */

/**
 * @todo this is temporary. This needs ASAP cleanup.
 */
#include <logging/log.h>
LOG_MODULE_REGISTER(net_mqtt_sock_tls, CONFIG_MQTT_LOG_LEVEL);

#include <errno.h>
#include <net/socket.h>
#include <net/mqtt.h>

#include "mqtt_os.h"

/**
 * @todo Remove this later.
 */
// #include "network_feature.h"
#include <net/socket.h>
#include <sys/__assert.h>

extern int32_t NetworkFeatureTLSConnectLte(uint16_t port, const uint8_t* server_addr);
int mqtt_client_tls_connect(struct mqtt_client *client)
{
#if 0
	const struct sockaddr *broker = client->broker;
	struct mqtt_sec_config *tls_config = &client->transport.tls.config;
	int ret;

	client->transport.tls.sock = zsock_socket(broker->sa_family,
						  SOCK_STREAM, IPPROTO_TLS_1_2);
	if (client->transport.tls.sock < 0) {
		return -errno;
	}

	MQTT_TRC("Created socket %d", client->transport.tls.sock);

#if defined(CONFIG_SOCKS)
	if (client->transport.proxy.addrlen != 0) {
		ret = setsockopt(client->transport.tls.sock,
				 SOL_SOCKET, SO_SOCKS5,
				 &client->transport.proxy.addr,
				 client->transport.proxy.addrlen);
		if (ret < 0) {
			return -errno;
		}
	}
#endif
	/* Set secure socket options. */
	ret = zsock_setsockopt(client->transport.tls.sock, SOL_TLS, TLS_PEER_VERIFY,
			       &tls_config->peer_verify,
			       sizeof(tls_config->peer_verify));
	if (ret < 0) {
		goto error;
	}

	if (tls_config->cipher_list != NULL && tls_config->cipher_count > 0) {
		ret = zsock_setsockopt(client->transport.tls.sock, SOL_TLS,
				       TLS_CIPHERSUITE_LIST, tls_config->cipher_list,
				       sizeof(int) * tls_config->cipher_count);
		if (ret < 0) {
			goto error;
		}
	}

	if (tls_config->sec_tag_list != NULL && tls_config->sec_tag_count > 0) {
		ret = zsock_setsockopt(client->transport.tls.sock, SOL_TLS,
				       TLS_SEC_TAG_LIST, tls_config->sec_tag_list,
				       sizeof(sec_tag_t) * tls_config->sec_tag_count);
		if (ret < 0) {
			goto error;
		}
	}

	if (tls_config->hostname) {
		ret = zsock_setsockopt(client->transport.tls.sock, SOL_TLS,
				       TLS_HOSTNAME, tls_config->hostname,
				       strlen(tls_config->hostname));
		if (ret < 0) {
			goto error;
		}
	}

	size_t peer_addr_size = sizeof(struct sockaddr_in6);

	if (broker->sa_family == AF_INET) {
		peer_addr_size = sizeof(struct sockaddr_in);
	}

	ret = zsock_connect(client->transport.tls.sock, client->broker,
			    peer_addr_size);
	if (ret < 0) {
		goto error;
	}

	MQTT_TRC("Connect completed");
	return 0;

error:
	(void) zsock_close(client->transport.tls.sock);
	return -errno;
#endif /* This code is disabled. */
char addr_string[100u];
memset(addr_string, 0x00, 100u);
struct sockaddr_in* ipv4_broker = (struct sockaddr_in*)&client->broker;
const char temp[] = "a20dpavs47nv66-ats.iot.ca-central-1.amazonaws.com";
const uint16_t temp_port = 8883u;
if ( NULL == zsock_inet_ntop(AF_INET, &ipv4_broker->sin_addr,
  addr_string, 100u))
{
  /**
   * @brief Error occurred during coverting ipv4 to string.
   * 
   */
  __ASSERT(0, "Err-MQTT-TRANSPORT: Coverting ipv4 to string");
}

return (int) NetworkFeatureTLSConnectLte(temp_port,
                                   (const uint8_t*)temp);
}

extern int32_t NetworkFeatureTLSWriteLte(const void* data, uint32_t data_size);
int mqtt_client_tls_write(struct mqtt_client *client, const uint8_t *data,
			  uint32_t datalen)
{
	uint32_t offset = 0U;
	int ret;

	while (offset < datalen) {
#if 0
		ret = zsock_send(client->transport.tls.sock, data + offset,
				 datalen - offset, 0);
#endif /* This code is disabled. */

    ret = (int) NetworkFeatureTLSWriteLte(data + offset, 
                                          (uint32_t)(datalen - offset));
		if (ret < 0) {
			return -errno;
		}

		offset += ret;
	}

	return 0;
}

int mqtt_client_tls_write_msg(struct mqtt_client *client,
			      const struct msghdr* message)
{
	int ret, i;
	size_t offset = 0;
	size_t total_len = 0;
  ssize_t len;
  size_t sent = 0;
  struct iovec* vec = NULL;
  uint8_t* ptr = NULL; 

	for (i = 0; i < message->msg_iovlen; i++)
  {
		total_len += message->msg_iov[i].iov_len;
	}

	while (offset < total_len) 
  {
#if 0
		ret = zsock_sendmsg(client->transport.tls.sock, message, 0);
#endif /* This code is disabled. */

	  len = 0;
    ret = -1;
    if (message)
    {
      for (i = 0; i < message->msg_iovlen; i++)
      {
        vec = message->msg_iov + i;
        sent = 0;

        if (vec->iov_len == 0)
        {
          continue;
        }

        while (sent < vec->iov_len)
        {
          ptr = (uint8_t *)vec->iov_base + sent;

          ret = NetworkFeatureTLSWriteLte(ptr, vec->iov_len - sent);
          if (ret < 0)
          {
            return -errno;
          }
    
          sent += ret;
        }
    
        len += sent;
      }
    }
    else
    {
      /**
     * @brief Error occurred during write_msg of msg.
     * 
     */
    __ASSERT(0, "Err-MQTT-TRANSPORT: Write_msg MSG is empty");
    }

		offset += ret;
		if (offset >= total_len)
    {
			break;
		}

		/* Update msghdr for the next iteration. */
		for (i = 0; i < message->msg_iovlen; i++)
    {
			if (ret < message->msg_iov[i].iov_len)
      {
				message->msg_iov[i].iov_len -= ret;
				message->msg_iov[i].iov_base =
					(uint8_t *)message->msg_iov[i].iov_base + ret;
				break;
			}

			ret -= message->msg_iov[i].iov_len;
			message->msg_iov[i].iov_len = 0;
		}
	}

	return 0;
}

extern int32_t NetworkFeatureTLSReadLte(void* data_buffer, 
                                        uint32_t data_buffer_size,
                                        bool blocking);
int mqtt_client_tls_read(struct mqtt_client *client, uint8_t *data, uint32_t buflen,
			 bool shall_block)
{

#if 0
	int flags = 0;
	int ret;

	if (!shall_block) {
		flags |= ZSOCK_MSG_DONTWAIT;
	}

	ret = zsock_recv(client->transport.tls.sock, data, buflen, flags);
	if (ret < 0) {
		return -errno;
	}
#endif /* This code is disabled. */

  int ret;

  /**
   * @brief Blocking is not supported.
   * 
   */
  ret = (int) NetworkFeatureTLSReadLte(data, buflen, shall_block);
  if (ret < 0)
  {
    return -errno;
	}

	return ret;
}

extern int32_t NetworkFeatureCloseSocket(void);
int mqtt_client_tls_disconnect(struct mqtt_client *client)
{
	int ret;

	MQTT_TRC("Closing socket %d", client->transport.tls.sock);
#if 0
	ret = zsock_close(client->transport.tls.sock);
#endif /* This code is disabled. */
  ret = NetworkFeatureCloseSocket();
	if (ret < 0) {
		return -errno;
	}

	return 0;
}
