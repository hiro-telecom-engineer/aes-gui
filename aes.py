import Crypto.Cipher.AES as AES
from Crypto.Util import Counter
from Crypto.Hash import CMAC

# ECB暗号化
def aes_ecb_enc_fnc( key , txt ):
	cipher = AES.new( key, AES.MODE_ECB )
	padding_txt = padding_fnc(txt)
	enc_txt = cipher.encrypt(padding_txt)
	return enc_txt


# ECB復号化
def aes_ecb_dec_fnc( key , txt ):
	decipher = AES.new( key, AES.MODE_ECB )
	dec_txt = decipher.decrypt(txt)
	return dec_txt


# CBC暗号化
def aes_cbc_enc_fnc( key , txt , iv ):
	cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
	padding_txt = padding_fnc(txt)
	enc_txt = cipher.encrypt(padding_txt)
	return enc_txt


# CBC復号化
def aes_cbc_dec_fnc( key , txt , iv ):
	decipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
	dec_txt = decipher.decrypt(txt)
	return dec_txt


# CTR暗号化
def aes_ctr_enc_fnc( key , txt , nonce , counter ):
	counter_size = 128 - len(nonce)*8
	ctr = Counter.new(counter_size, prefix=nonce, little_endian=False, initial_value=counter)
	cipher = AES.new(key=key, mode=AES.MODE_CTR , counter=ctr)
	enc_txt = cipher.encrypt(txt)
	return enc_txt


# CTR復号化
def aes_ctr_dec_fnc( key , txt , nonce , counter ):
	counter_size = 128 - len(nonce)*8
	ctr = Counter.new(counter_size, prefix=nonce, little_endian=False, initial_value=counter)
	decipher = AES.new(key=key, mode=AES.MODE_CTR , counter=ctr)
	dec_txt = decipher.decrypt(txt)
	return dec_txt


# MAC生成
def aes_cmac_fnc( key , txt ):
	h = CMAC.new(key, txt, ciphermod=AES)
	mac = h.digest()
	return mac


# パディング(PKCS#5、PKCS#7)
def padding_fnc( data ):
	padding_data = data
	if 0 != (len(data) % 16):
		padding_size = 16 - (len(data) % 16)
		for i in range(padding_size):
			padding_data += padding_size.to_bytes(1, 'little')
	return padding_data
