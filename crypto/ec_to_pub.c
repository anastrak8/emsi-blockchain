#include "hblk_crypto.h"
/**
* ec_to_pub :: extracing the value of the puplic key from an EC_KEY STRUCTURE
*	(in this case its our EC_KEY that we created with ec_create func)
		:: RETURNS A POINTER OF A PUBLIC KEY , OR NULL UPON FAILURE
* @key :: pointer of the EC_KEY structure 
* @pub :: stores the address of the public key ...
* NOTICE :: the EC_PUB_LEN macro is defined at hblk_crypto.h
* documentations :: https://docs.huihoo.com/doxygen/openssl/1.0.1c/ec__key_8c.html  &&
*	https://www.openssl.org/docs/man1.0.2/man3/EC_POINT_new.html
**/
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]){
	
	//EC_POINT *  to store the result of EC_KEY_get0_public_key (const EC_KEY *key)	
	const EC_POINT * ec_point;
	const EC_GROUP * ec_group;
	//verifing if key or pub is null :: in case return null and  do nothing ofc
	if (!key || !pub)
		return NULL;
	//generating a EC_POINT && EC_GROUP pointer based on the EC_KEY pointer we've passed
	ec_point = EC_KEY_get0_public_key(key);
	ec_group = EC_KEY_get0_group(key); 
	if (!EC_POINT_point2oct(ec_group, ec_point, POINT_CONVERSION_UNCOMPRESSED, pub,EC_PUB_LEN, NULL)){
			//free ec_point && ec_group in failure case and return with a  null result :(
			EC_POINT_free((EC_POINT *)ec_point);
			EC_GROUP_free((EC_GROUP*)ec_group);
			return NULL;
	}
	return pub;
}
