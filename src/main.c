#include <node_api.h>
#include <string.h>
#include "monocypher.h"

napi_value crypto_key_exchange_pub_key(napi_env env, napi_callback_info info)
{
  napi_status status;
  napi_value key;
  size_t argc = 1;
  napi_value argv[1];
  void *arr = NULL;
  uint8_t pubKey[32];
  uint8_t secretKey[32];
  
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
  }
  size_t length;
  status = napi_get_buffer_info(env, argv[0], &arr, &length);

  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Cannot get buffer");
  }
  uint8_t *ptr = (uint8_t *) arr;
  memcpy(secretKey, ptr, length);

  crypto_key_exchange_public_key(pubKey, secretKey);
  status = napi_create_buffer_copy(env, length, pubKey, arr, &key);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to create return value");
  }

  return key;
}

napi_value Init(napi_env env, napi_value exports)
{
  napi_status status;
  napi_value fn;

  status = napi_create_function(env, NULL, 0, crypto_key_exchange_pub_key, NULL, &fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "crypto_key_exchange_pub_key", fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)