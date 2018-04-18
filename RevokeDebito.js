
card = new Card();
atr = card.reset(Card.RESET_COLD);
print("");

//constantes crifrado
var crypto = new Crypto();
var deskey = new Key();
//constantes TLVs
var CLArecord = "8C D2 00 08";


var Kt = new ByteString("AA 00 AA 01 AA 02 AA 03", HEX);

var Kc = new ByteString("DD 00 DD 01 DD 02 DD 03", HEX);

var Kcf = new ByteString("B0 B1 B2 B3 B4 B5 B6 B7", HEX);

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

//Lanzar inquire
var reference = crypto.generateRandom(4);
resp = card.plainApdu(new ByteString("80 E4 03 00 04" + reference, HEX));
print("Código SW: " + card.SW.toString(16));
print("inquire " + resp);
resp = card.plainApdu(new ByteString("80 C0 00 00 08", HEX));
print ("Respuesta a la autenticación " + resp);

//Calcular MAC
var Balance = resp.bytes(5,3);
print("Balance0: "+Balance);
print("Balance1: "+Balance.toSigned());
var transType = resp.bytes(4,1);
var ATREF = resp.bytes(8,6);
var TTREFC = resp.bytes(17,4);
var TTREFD = resp.bytes(21,4);

deskey.setComponent(Key.DES, Kcf);
var vectorI = new ByteString("00 00 00 00 00 00 00 00",HEX);
var calcularMac = new ByteString(reference + transType + Balance + ATREF + "00 00",HEX);
var calcularMacCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,calcularMac, vectorI);
var todoCifrado = calcularMacCifrado.right(8);
var Mac4 = todoCifrado.left(4);
print("Comprobar coincidencia MAC: "+Mac4);
print("Comprobar con devuelto: "+Mac4 +"<-->"+resp.bytes(0,4));

//hasta aquí inquire
//hacer calculos evolviendo el mismo importe que se cargó
var valorDevuelto = new ByteString("00 04 E4",HEX);
print ("valorDevuelto" + valorDevuelto);

ATREF = ATREF.add(1);
Balance = Balance.add(valorDevuelto.toSigned());
var revocar = new ByteString("E8",HEX).concat(Balance).concat(TTREFD).concat(ATREF).concat(new ByteString("00 00",HEX));
deskey.setComponent(Key.DES, Kcf);
var VI = new ByteString("0000000000000000",HEX);
var cifrado =  crypto.encrypt(deskey, Crypto.DES_CBC,revocar, VI);
var MAC = cifrado.right(8).left(4);
resp = card.plainApdu(new ByteString("80 E8 00 00 04",HEX).concat(MAC));
print ("Respuesta del revoke" + resp);
print("Código SW: " + card.SW.toString(16));
//llamada a inquire para comprobar
load("entregable11.js");