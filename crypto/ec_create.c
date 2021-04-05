#include "hblk_crypto.h"

EC_KEY *ec_create(void)
{
	/**
	 * ec_create - create EC key pair(private && public)
	 *
	 * Returning: pointer to created EC_KEY struct
	 */
	//CREATING A EC_KEY STRUCTURE POINTER 
	EC_KEY * ec_key;
	
	//SPECIFIYING CURVE NAME FUNCTION
		//NOTICE :: EC_CURVE MACRO IS DECLARED ON hblk_crypto.h
	ec_key = EC_KEY_new_by_curve_name(EC_CURVE);
	//TESTING IF THERE WAS ANY ERROR CREATING THE STRUCTURE
	if (!ec_key || ec_key == NULL)
			return NULL;
	//generating the key and checking if its went correctly
	if (!EC_KEY_generate_key(ec_key))
	{
		//FREES THE ec_key Object (IN THIS CASE IF THERE WAS AN ERROR GENERATING)
		EC_KEY_free(ec_key);
		return NULL;
	}
	//returning the pointer of the EC_KEY OBJECT 
	return ec_key;
}
