#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>
#include <stdio.h>

#include "openssl/bio.h"

static const char* engine_id = "fake";
static const char* engine_name = "fakeEngine";

EVP_PKEY* generate_evp_pkey(const char* file)
{
    printf("FAKEENGINE: generate_evp_pkey\n");
    int j, ret = 0;
    BIO* in;
    EVP_PKEY* pkey = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0)
    {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    j = ERR_R_PEM_LIB;
    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);

    if (pkey == NULL)
    {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
        goto end;
    }

end:
    if (in != NULL)
        BIO_free(in);
    return pkey;
}

EVP_PKEY* load_key_cb(ENGINE* e, const char* key_id, UI_METHOD* ui_method, void* callback_data)
{
    printf("FAKEENGINE: load_key_cb\n");
    return generate_evp_pkey("/home/qinzhili/workspaces/palladium-project/build/src/client-key.pem");
}
static int bind(ENGINE* e, const char* id)
{
    int ret = 0;
    printf("FAKEENGINE: bind\n");

    if (!ENGINE_set_id(e, engine_id))
    {
        fprintf(stderr, "set if failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name))
    {
        printf("ENGINE_set_name failed\n");
        goto end;
    }
    ENGINE_set_load_privkey_function(e, load_key_cb);
    ret = 1;
end:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
