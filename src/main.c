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

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Failed to parse arguments");
  }
  size_t length;
  status = napi_get_buffer_info(env, argv[0], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get buffer");
  }
  uint8_t *secretKey = (uint8_t *)arr;

  crypto_key_exchange_public_key(pubKey, secretKey);
  status = napi_create_buffer_copy(env, length, pubKey, arr, &key);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to create return value");
  }

  return key;
}

napi_value crypto_signature(napi_env env, napi_callback_info info)
{
  napi_status status;
  napi_value sign;
  size_t argc = 3;
  napi_value argv[3];
  void *arr = NULL;
  size_t length;
  uint8_t signature[64];

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Failed to parse arguments");
  }
  /* ---------------- GET SECRET KEY --------------------*/
  status = napi_get_buffer_info(env, argv[0], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get SECRET KEY");
  }
  uint8_t *secretKey = (uint8_t *)arr;
  //-------------------------------------------------------
  /* ---------------- GET PUBLIC KEY --------------------*/
  status = napi_get_buffer_info(env, argv[1], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get PUBLIC KEY");
  }
  uint8_t *pubKey = (uint8_t *)arr;
  //-------------------------------------------------------
  /* ---------------- GET MESSAGE ------------------*/
  status = napi_get_buffer_info(env, argv[2], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get MESSAGE");
  }
  uint8_t *message = (uint8_t *)arr;
  //-------------------------------------------------------
  crypto_sign(signature, secretKey, pubKey, message, length);  
  status = napi_create_buffer_copy(env, 64, signature, arr, &sign);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to create return value");
  }

  return sign;
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

  status = napi_create_function(env, NULL, 0, crypto_signature, NULL, &fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "crypto_signature", fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)