#include <Python.h>
#include <cauth2.h>

_Static_assert(
   sizeof(mbedtls_md_type_t)==sizeof(int),
   "Error. Realign for int"
);

typedef struct {
   PyObject_HEAD
   const char *hmac_secret_key_dyn;
   size_t hmac_secret_key_size;
   mbedtls_md_type_t hmac_alg_type;
   const char *totp_secret_key_dyn;
   size_t totp_secret_key_size;
   mbedtls_md_type_t totp_alg_type;
} C_RAW_DATA_OBJ;

struct panelAuthConst_t {
   const char *name;
   int value;
} PANEL_AUTH_CONST[] = {
   {"ALG_SHA1_DEFAULT", MBEDTLS_MD_SHA1},
   {"ALG_SHA256", MBEDTLS_MD_SHA256},
   {"ALG_SHA512", MBEDTLS_MD_SHA512},
   {NULL}
};

#ifdef P_DEBUG
 #define PANEL_DEBUG(std, ...) \
    fprintf(std, __VA_ARGS__);
#else
 #define PANEL_DEBUG(std, ...)
#endif

#define PANEL_ERROR(err_msg, errNumber) \
   {\
      PyErr_SetString(PyExc_Exception, err_msg);\
      return errNumber;\
   }

#define ERR_CANT_SHOW_ERR (char *)"Fail on parse error format"
static const char *error_msg_dynamic(const char *fmt, ...)
{
   int err;
   char *msg_fmt;
   va_list args;

   va_start(args, fmt);
   err=vasprintf(&msg_fmt, fmt, args);
   va_end(args);

   if (err>=0)
      return (const char *)msg_fmt;

   return ERR_CANT_SHOW_ERR;
}

#define PANEL_ERROR_FMT(errNumber, valueFmt, ...) \
   {\
      char *_p=(char *)error_msg_dynamic(valueFmt, __VA_ARGS__); \
      PyErr_SetString(PyExc_Exception, _p);\
      if (_p!=ERR_CANT_SHOW_ERR)\
         free(_p);\
      return errNumber;\
   }

#define CLEAR_AND_FREE(__p, __s) \
   memset((void *)__p, 0, __s); \
   free((void *)__p); \
   __p=NULL;

#define CLEAR_AND_FREE_SAFE(__p, __s) \
   if (__p) { \
      CLEAR_AND_FREE(__p, __s) \
   }

static PyObject *c_raw_data_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
   C_RAW_DATA_OBJ *self;

   if (!(self=(C_RAW_DATA_OBJ *)type->tp_alloc(type, 0)))
      PANEL_ERROR("C_RAW_DATA_OBJ error", NULL)

   PANEL_DEBUG(stdout, "New object created at %p\n", self)

   return (PyObject *)self;
}

static int c_raw_data_obj_init(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   const char *errMsg;
   char
      *kwlist[] = {"hmacSecretKey", "totpSecretKey", "hmacAlgType", "totpAlgType", NULL},
      *hmacSecretKey, *totpSecretKey=NULL;

   self->hmac_secret_key_dyn=NULL;
   self->totp_secret_key_dyn=NULL;
   self->hmac_alg_type=MBEDTLS_MD_SHA256;
   self->totp_alg_type=MBEDTLS_MD_SHA1;

   if (!PyArg_ParseTupleAndKeywords(
      args, kwds, "s|sII", kwlist,
      &hmacSecretKey, &totpSecretKey, &self->hmac_alg_type, &self->totp_alg_type
   )) PANEL_ERROR("Error on parse on init", 11)

   if (!(self->hmac_secret_key_size=strlen(hmacSecretKey)))
      PANEL_ERROR("Empty HMAC secret key", 12)

   if (!(self->hmac_secret_key_dyn=malloc(++(self->hmac_secret_key_size))))
      PANEL_ERROR("Could not alloc memory to store secret key", 4)

   strncpy((char *)self->hmac_secret_key_dyn, hmacSecretKey, self->hmac_secret_key_size--);

   if (totpSecretKey) {
      if ((err=check_base32_oauth_key_valid(
            NULL, totpSecretKey,
            self->totp_secret_key_size=strlen(totpSecretKey), self->totp_alg_type
      ))) {
         errMsg="Empty Auth2 TOTP Base32 secret key or C function check_base32_oauth_key_valid() error";
         goto totpSecretKey_ERROR;
      }

      if (!(self->totp_secret_key_dyn=malloc(++(self->totp_secret_key_size)))) {
         err=15;
         errMsg="Could not alloc memory to store Auth2 TOTP";
         goto totpSecretKey_ERROR;
      }

      strncpy((char *)self->totp_secret_key_dyn, totpSecretKey, self->totp_secret_key_size--);
   }

   return 0;

totpSecretKey_ERROR:
   memset((void *)self->hmac_secret_key_dyn, 0, self->hmac_secret_key_size);
   free((void *)self->hmac_secret_key_dyn);
   self->hmac_secret_key_dyn=NULL;
   PANEL_ERROR(errMsg, err)
}

static void c_raw_data_obj_dealloc(C_RAW_DATA_OBJ *self)
{
   PANEL_DEBUG(stdout, "Dealloc secret key\n")
   CLEAR_AND_FREE_SAFE(self->hmac_secret_key_dyn, self->hmac_secret_key_size)
   PANEL_DEBUG(stdout, "Dealloc totp secret key\n")
   CLEAR_AND_FREE_SAFE(self->totp_secret_key_dyn, self->totp_secret_key_size)
   PANEL_DEBUG(stdout, "Dealloc object\n")
   Py_TYPE(self)->tp_free((PyObject *)self);
   PANEL_DEBUG(stdout, "Free object\n")
}

static PyObject *get_auth_totp(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   uint32_t c_result;

   if (self->totp_secret_key_dyn) {
      if ((err=cauth_2fa_auth_code(
         &c_result,
         self->totp_alg_type,
         (uint8_t *)self->totp_secret_key_dyn,
         self->totp_secret_key_size,
         TRUE, 0, 30, NULL, 6
      ))) PANEL_ERROR_FMT(NULL, "C error @ cauth_2fa_auth_code with error code = %d", err)
   } else
      PANEL_ERROR("Could not get Auth TOTP. Please initilize with Base32 Auth secret key", NULL)

   return PyLong_FromLong((long int)c_result);
}

static PyObject *sign_message(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   static char *kwlist[] = {"messageStr", NULL};
   char *strMsg;
   static void *signed_message_ptr;
   size_t signed_message_size;
   PyObject *ret;

   if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &strMsg))
      PANEL_ERROR("Can't parse message to be assigned", NULL)

   if ((err=sign_message_dynamic(
      (void **)&signed_message_ptr, &signed_message_size,
      self->hmac_alg_type,
      (uint8_t *)self->hmac_secret_key_dyn, self->hmac_secret_key_size,
      (uint8_t *)strMsg, strlen(strMsg)
   ))) PANEL_ERROR_FMT(NULL, "Sign message error @ sign_message_dynamic with err = %d", err)

   ret=Py_BuildValue("y#", signed_message_ptr, signed_message_size);
   CLEAR_AND_FREE(signed_message_ptr, signed_message_size)

   if (ret)
      return ret;

   PANEL_ERROR("Error. Can't convert binary to string", NULL)
}

static PyMethodDef panelauth_methods[] = {
    {"getAuthTotp", (PyCFunction)get_auth_totp, METH_NOARGS, "Get current TOTP authentication code with given initialized secret."},
    {"signMessage", (PyCFunction)sign_message, METH_VARARGS|METH_KEYWORDS, "Signs a message with a given private key"},
    {NULL}
};

static PyTypeObject PANEL_AUTH_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name="Panel Auth Type module",
    .tp_doc="This module implements AUTH2 and HMAC signature for PLC Control panel and IoT devices",
    .tp_basicsize=sizeof(C_RAW_DATA_OBJ),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
    .tp_new=c_raw_data_obj_new,
    .tp_init=(initproc)c_raw_data_obj_init,
    .tp_dealloc=(destructor)c_raw_data_obj_dealloc,
    .tp_methods=panelauth_methods
};

static PyModuleDef PANEL_AUTH_module = {
    PyModuleDef_HEAD_INIT,
    .m_name="PANEL_AUTH module",
    .m_doc="PLC panel / IoT AUTH2 and HMAC protocol modules for Python 3 using C library",
    .m_size=-1,
};

PyMODINIT_FUNC PyInit_panelauth(void)
{
   PyObject *m;
   struct panelAuthConst_t *panelConst;

   PANEL_DEBUG(stdout, "Check is panel is ready\n")
   if (PyType_Ready(&PANEL_AUTH_Type)<0)
      PANEL_ERROR("\n\"Can't initialize module Panel Auth\"\n", NULL)

   PANEL_DEBUG(stdout, "Creating module ...\n")
   if (!(m=PyModule_Create(&PANEL_AUTH_module)))
      PANEL_ERROR("\nCannot create module \"PANEL_AUTH_module\"\n", NULL)

   PANEL_DEBUG(stdout, "Module %p created\n", m);
   if (PyModule_AddObject(m, "create", (PyObject *) &PANEL_AUTH_Type)<0)
      PANEL_ERROR("\nCannot create module \"panelauth\" from \"PANEL_AUTH_Type\"\n", NULL)

   PANEL_DEBUG(stdout, "Object added\nAdding constants ...\n");

   panelConst=PANEL_AUTH_CONST;

   while (panelConst->name) {
      if (PyModule_AddIntConstant(m, panelConst->name, (long int)panelConst->value))
         PANEL_ERROR("Could not add const value", NULL)

      panelConst++;
   }

   return m;
}

