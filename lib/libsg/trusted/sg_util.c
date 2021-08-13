#include "sg_util.h"
#include "sg_t.h" 
#include "errlist.h"
#include "xmem.h"
#include "sgx_tseal.h"
#include "sg_common.h"
#include "sg_stdfunc.h"
//#define DEBUG_SG_UTIL 1


int
seal(const char *filename, uint8_t *buf, size_t len)
{

#ifdef __ENCLAVE__

#ifdef DEBUG_SG_UTIL
    edividerWithText("Data to be Sealed");
    eprintf("len %d\n%s\n", len, hexstring(buf, len));
    edivider();
#endif
	size_t slen = sgx_calc_sealed_data_size(0, len);
	if (slen == 0xFFFFFFFF) {
#ifdef DEBUG_SG_UTIL
		eprintf("Error, sgx_calc_sealed_data_size failed\n");
#endif
		return ER_SGX_SEAL;
	}

	sgx_sealed_data_t *sbuf = (sgx_sealed_data_t *)xmalloc(slen);
	int ret = (int)sgx_seal_data(0, NULL, len, buf, slen, sbuf);
	if (ret) {
#ifdef DEBUG_SG_UTIL
		eprintf("Error, sgx_seal_data failed\n");
#endif
		xfree(sbuf);
		return ER_SGX_SEAL;
	}
#ifdef DEBUG_SG_UTIL
edividerWithText("Sealed Data");
eprintf("len %d\n%s\n", slen, hexstring(sbuf, slen));
edivider();
#endif
	// Store to disk
	ocall_store(&ret, filename, (uint8_t *)sbuf, slen);
    if (ret) {
        eprintf("\t+ %s : Error, ocall_store failed with 0x%08x\n", __FUNCTION__, ret);
        exit(1);
    }
    
/*#ifdef DEBUG_SG_UTIL
    uint8_t *unsealbuf = malloc(16384);
    uint32_t unsealbuf_sz = 16384;
    ret = sgx_unseal_data(sbuf, NULL, NULL, unsealbuf, &unsealbuf_sz);
    if (ret != SGX_SUCCESS) {
        eprintf("\t+ %s : unsealing failed 0x%08x\n", __FUNCTION__, ret);
        exit(1);
    }
    
edividerWithText("Unsealed Data");
eprintf("len %d\n%s\n", unsealbuf_sz,  hexstring(unsealbuf, unsealbuf_sz));
edivider();

#endif*/
    

    // Propagate error
	xfree(sbuf);
	return ret;
#endif // __ENCLAVE__

}

/*
 *
 * @return : 0 on success, >0 else
 */
int
unseal(const char *filename, uint8_t **buf, size_t *len)
{
#ifdef __ENCLAVE__
	sgx_sealed_data_t *sbuf;
	uint8_t *tmp;
	size_t tmp_len;
	int ret;

    // Check if file exists
    sgx_status_t status = ocall_access(&ret, filename);
    if (ret) {
#ifdef DEBUG_SG_UTIL
        eprintf("\t+ %s : File %s does not exist\n", __FUNCTION__, filename);
#endif
    return ER_NOEXIST; 
    }

	// Get size of file
	status = ocall_load_len(&ret, filename, &tmp_len);
	if (ret) {
        eprintf("\t+ %s : Error, ocall_load_len returned %d\n", __FUNCTION__, ret);
		return ret;
	}
#ifdef DEBUG_SG_UTIL
    eprintf("\t+ %s : Loading sealed file of size %d\n", __FUNCTION__, tmp_len);
#endif

    // Check if file is empty
	if (tmp_len == 0) {
    return 0;
  }

	// Load file
	tmp = xmalloc(sizeof(uint8_t) * tmp_len);
	status = ocall_load(&ret, filename, tmp, tmp_len);
	if (ret) {
		xfree(tmp);
		return ret;
	}
#ifdef DEBUG_SG_UTIL
    edividerWithText("Sealed Data");
    eprintf("len %d\n%s\n", tmp_len, hexstring(tmp, tmp_len));
    edivider();
#endif
	// Get size of unsealed data
	*len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)tmp);
	if (*len == 0xFFFFFFFF) {
		eprintf("\t+ %s : Error, sgx_get_encrypt_txt_len failed\n", __FUNCTION__);
		*len = 0;
		xfree(tmp);
		return ER_SGX_UNSEAL;
	}

	// Unseal
	*buf = xmalloc(*len);
	ret = (int)sgx_unseal_data((sgx_sealed_data_t *)tmp, NULL, 0, *buf, (uint32_t *)len);
	if (ret) {
		eprintf("\t+ %s : Error, sgx_unseal_data failed\n", __FUNCTION__);
        ret = ER_SGX_UNSEAL;
        *len = 0;
		xfree(*buf);
	}

	free(tmp);
	return ret;
  #endif //__ENCLAVE__
}

