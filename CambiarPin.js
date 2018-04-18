//cargamos el fichero de autenticar
load("entregable8.js");
print("Cambiando pin");
deskey.setComponent(Key.DES, Ks);

//Construir pin
var pin = new ByteString("30 31 32 33 34 35 36 37", HEX);
var pinCifrado = crypto.encrypt(deskey, Crypto.DES_ECB, pin);
var resp = card.plainApdu(new ByteString("80 20 06 00 08",HEX).concat(pinCifrado));
print ("Submit SW Status: " + card.SW.toString(16));

//cambio de pin 
var pin2 = new ByteString("00 01 02 03 04 05 06 07 08",HEX);
var resp = card.plainApdu(new ByteString("80 24 08 00 08",HEX));
print ("Submit SW Status: " + card.SW.toString(16));

var pin2Cifrado = crypto.encrypt(deskey, Crypto.DES_ECB, pin2);