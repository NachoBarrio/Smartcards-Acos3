
card = new Card();
atr = card.reset(Card.RESET_COLD);
print("");

//variables crifrado
var crypto = new Crypto();
var deskey = new Key();


print("Constante Kt");
var Kt = new ByteString("AA 00 AA 01 AA 02 AA 03", HEX);

print("Constante Kc");
var Kc = new ByteString("DD 00 DD 01 DD 02 DD 03", HEX);

var aleatorioC = card.plainApdu(new ByteString("80 84 00 00 08", HEX));

deskey.setComponent(Key.DES, Kt);
var cifrado =  crypto.encrypt(deskey, Crypto.DES_ECB, aleatorioC);
var aleatorioT = crypto.generateRandom(8);
var encriptado = cifrado.concat(aleatorioT);
print("");

//autenticar
resp = card.plainApdu(new ByteString("80 82 00 00 10", HEX).concat(encriptado));
print("Código SW: " + card.SW.toString(16));
print("");
resp = card.plainApdu(new ByteString("80 C0 00 00 08", HEX));
print ("Respuesta a la autenticación " + resp);

deskey.setComponent(Key.DES, Kc);
var encriptadoKS = crypto.encrypt(deskey, Crypto.DES_ECB, aleatorioC);
var paso1  = encriptadoKS.xor(aleatorioT);
deskey.setComponent(Key.DES, Kt);
//Key session
Ks = crypto.encrypt(deskey, Crypto.DES_ECB, paso1);

deskey.setComponent(Key.DES, Ks);
var checkeo = crypto.encrypt(deskey, Crypto.DES_ECB, aleatorioT);

print("Comprobando autenticador");
print(" variable de checkeo: "+checkeo.toString());
print("Comprobando respuesta");
print(" respuesta: "+resp.toString());

//PASO 2
var vectorIMac = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX)).add(1);
print("paso 1");
var fileBytes = ByteString.valueOf(52,1);
print("paso 2: "+fileBytes);
var MacClaro = new ByteString("89 04 8C B2 08 00 97 01",HEX).concat(fileBytes);
print("paso 3");
var MacRelleno = MacClaro.pad(Crypto.ISO9797_METHOD_2, true);
var MacCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacRelleno, vectorIMac);
var todoCifrado = MacCifrado.right(8);
var Mac4 = todoCifrado.left(4);
//PASO 3
print("paso 4");
var apduEnviar = new ByteString("97 01"+fileBytes+"8E 04"+Mac4,HEX);
print("paso 5");
print(" Posicionarte en fichero ");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C4", HEX));
print("");
resp = card.sendApdu(0x8C, 0xB2, 0x08, 0x00, apduEnviar);
print("Código SW: " + card.SW.toString(16));
print("");
//GET RESPONSE
//resp = card.plainApdu(new ByteString("80 C0 00 00 0C", HEX));
// 52nb, proximo multiplo 56, +15 = 71
resp = card.sendApdu(0x80, 0xC0, 0x00, 0x00, 71);
print ("Respuesta a la autenticación " + resp);

//Calcular MAC
//PASO 6
var TLVTarjeta = "89 04 8C B2 08 00 87";
var L87 = resp.bytes(1,1);
print ("L87 " + L87);
var Pi = resp.bytes(2,1);
print ("Pi " + Pi);
var Encriptado = resp.bytes(3,56);
print ("Encriptado " + Encriptado);
var S1S2 = resp.bytes(61,2); 
print ("S1S2 " + S1S2);
TLVTarjeta = new ByteString(TLVTarjeta.concat(L87 + Pi + Encriptado + "99 02" + S1S2),HEX);
var MacComprobarRelleno = TLVTarjeta.pad(Crypto.ISO9797_METHOD_2, true);
var vectorIMac2 = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX)).add(2);
var MacComprobarCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacComprobarRelleno, vectorIMac2);
var todoCifrado = MacComprobarCifrado.right(8);
var Mac4 = todoCifrado.left(4);
print("Comprobar coincidencia MAC: "+Mac4+"<--->"+resp.bytes(resp.length-4,4));

//PASO 7 descifrar Encripted
var descifrado = crypto.decrypt(deskey, Crypto.DES_CBC,Encriptado,vectorIMac2);
//Valor Pi = 04 para la resta siguiente
var msgClaro = descifrado.bytes(0,Encriptado.length - Pi.toString());
print("Long :"+msgClaro.length);
print("Long ENc :"+Encriptado.length);
print("Texto en claro: "+msgClaro.toString(ASCII));

