
card = new Card();
atr = card.reset(Card.RESET_COLD);
print("");

//constantes crifrado
var crypto = new Crypto();
var deskey = new Key();
//constantes TLVs
var CLArecord = "8C D2 00 08";


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
// PASO 1
Ks = crypto.encrypt(deskey, Crypto.DES_ECB, paso1);
print("paso");
deskey.setComponent(Key.DES, Ks);
var checkeo = crypto.encrypt(deskey, Crypto.DES_ECB, aleatorioT);
print("Comprobando autenticador");
print(" variable de checkeo: "+checkeo.toString());
print("Comprobando respuesta");
print(" respuesta: "+resp.toString());

//Escribir fichero 8DC4
//PASO 2
var msgEnviar = new ByteString("MASTER SSDDEE.2018.Ignacio Barrio Santos",ASCII);
var msgRelleno = msgEnviar.pad(Crypto.ISO9797_METHOD_2, true);
print("paso 1");
//PASO 3
var lengthRelleno = (msgRelleno.length - msgEnviar.length).toString(16);
print(lengthRelleno);
//PASO 4
var vectorI = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX));
print("paso 2");
//PASO 5
var msgEncriptado = crypto.encrypt(deskey, Crypto.DES_CBC, msgRelleno, vectorI);
print("paso 3");
//TLV87

var H87 = "87";
var L87 = (msgEncriptado.length+1).toString(16);
var Pi = lengthRelleno;

if(lengthRelleno < 16){
	Pi = "0" + Pi;
}

var TLV87 = "87 "+L87+Pi+msgEncriptado;
var TLV89 = "89 04 8C D2 08 00";
var TLV8E = "8E 04";
//PASO 6
var vectorIMac = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX)).add(1);
var MacClaro = new ByteString(TLV89.concat(TLV87),HEX);
print("MacClaro: "+MacClaro.toString());
var MacRelleno = MacClaro.pad(Crypto.ISO9797_METHOD_2, true);
var MacCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacRelleno, vectorIMac);
print("paso 4");
var todoCifrado = MacCifrado.right(8);
var Mac4 = todoCifrado.left(4);
//PASO 7
var apduEnviar = new ByteString(TLV87 + TLV8E + Mac4,HEX);
//var apduEnviar = new ByteString(MacClaro.concat(Mac4),HEX);
print("paso 5 "+apduEnviar.toString(16));
//PASO 8
print(" Posicionarte en fichero ");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C4", HEX));
print("");
//PASO 9
resp = card.sendApdu(0x8C, 0xD2, 0x08, 0x00, apduEnviar);
print("Código SW: " + card.SW.toString(16));
print("");

//Get Response
print("");
resp = card.plainApdu(new ByteString("80 C0 00 00 0C", HEX));
print ("Respuesta a la autenticación " + resp);

//verificar MAC
var TLV89 = new ByteString("89 04 8C D2 08 00 99 02 90 00",HEX);
var MacComprobarRelleno = TLV89.pad(Crypto.ISO9797_METHOD_2, true);
var vectorIMac2 = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX)).add(2);
var MacComprobarCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacComprobarRelleno, vectorIMac2);
var todoCifrado = MacComprobarCifrado.right(8);
var Mac4 = todoCifrado.left(4);
print("Comprobar coincidencia MAC: "+Mac4);