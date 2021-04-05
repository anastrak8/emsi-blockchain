#include "hblk_crypto.h"
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN]){
	EC_KEY *key;
	EC_GROUP *group;
	EC_POINT *point;

	if (!pub)
		return NULL;
	//generating a key with ec_curve func
	key = EC_KEY_new_by_curve_name(EC_CURVE);
	
	if (!key)
		return NULL;
	//group based on our key
	group = (EC_GROUP *)EC_KEY_get0_group(key);
	// ec_point based on the group
	point = EC_POINT_new(group);
	if (!point)
	{
		EC_KEY_free(key);
		return NULL;
	}

	if (!EC_POINT_oct2point(group, point, pub, EC_PUB_LEN, NULL) || !EC_KEY_set_public_key(key,point))
		goto out;

	EC_POINT_free(point);
	return key;
	out:
	EC_KEY_free(key);
	EC_POINT_free(point);
	return NULL;
}
