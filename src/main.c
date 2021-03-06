#include <node_api.h>
#include <string.h>
#include "monocypher.h"

napi_value key_exchange_public_key(napi_env env, napi_callback_info info)
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
  status = napi_create_buffer_copy(env, 32, pubKey, arr, &key);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to create return value");
  }

  return key;
}

napi_value sign(napi_env env, napi_callback_info info)
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

napi_value key_exchange(napi_env env, napi_callback_info info)
{
  napi_status status;
  napi_value key;
  size_t argc = 2;
  napi_value argv[2];
  void *arr = NULL;
  size_t length;
  uint8_t sharedKey[32];

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Failed to parse arguments");
  }
  /* ---------------- GET MY SECRET KEY --------------------*/
  status = napi_get_buffer_info(env, argv[0], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get MY SECRET KEY");
  }
  uint8_t *mySecretKey = (uint8_t *)arr;
  //-------------------------------------------------------
  /* ---------------- GET THEIR PUBLIC KEY --------------------*/
  status = napi_get_buffer_info(env, argv[1], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get THEIR PUBLIC KEY");
  }
  uint8_t *theirPubKey = (uint8_t *)arr;
  //-------------------------------------------------------
  
  crypto_key_exchange(sharedKey, mySecretKey, theirPubKey);  
  status = napi_create_buffer_copy(env, 32, sharedKey, arr, &key);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to create return value");
  }

  return key;
}

napi_value check(napi_env env, napi_callback_info info)
{
  napi_status status;
  napi_value validation;
  size_t argc = 3;
  napi_value argv[3];
  void *arr = NULL;
  size_t length;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Failed to parse arguments");
  }
  /* ---------------- GET SIGNATURE --------------------*/
  status = napi_get_buffer_info(env, argv[0], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get SIGNATURE");
  }
  uint8_t *signature = (uint8_t *)arr;
  //-------------------------------------------------------
  /* ---------------- GET PUBLIC KEY --------------------*/
  status = napi_get_buffer_info(env, argv[1], &arr, &length);

  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Cannot get THEIR PUBLIC KEY");
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
  int ret = crypto_check(signature, pubKey, message, length);  
  status = napi_create_int32(env, ret, &validation);

  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value");
  }

  return validation;
}

napi_value Init(napi_env env, napi_value exports)
{
  napi_status status;
  napi_value fn;

  status = napi_create_function(env, NULL, 0, key_exchange_public_key, NULL, &fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "key_exchange_public_key", fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  status = napi_create_function(env, NULL, 0, sign, NULL, &fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "sign", fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  status = napi_create_function(env, NULL, 0, key_exchange, NULL, &fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "key_exchange", fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  status = napi_create_function(env, NULL, 0, check, NULL, &fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }

  status = napi_set_named_property(env, exports, "check", fn);
  if (status != napi_ok)
  {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)