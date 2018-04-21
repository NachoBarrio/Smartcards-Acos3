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

print("Constante Kcr");
var Kcr = new ByteString("90 91 92 93 94 95 96 97", HEX);

print("Constante Kd");
var Kd = new ByteString("80 81 82 83 84 85 86 87", HEX);

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

//PASO 2
var msgEnviar = new ByteString("00 01 02 03",HEX);
var msgRelleno = msgEnviar.pad(Crypto.ISO9797_METHOD_2, true);
print("paso 1");
//PASO 4
var vectorI = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX));
print("paso 2");
//PASO 5
var msgEncriptado = crypto.encrypt(deskey, Crypto.DES_CBC, msgRelleno, vectorI);
print("paso 3");

//TLV87

var H87 = "87";
var L87 = "0" + (msgEncriptado.length+1).toString(16);
var Pi = "0" + (msgRelleno.length - 4).toString(16);

var TLV87 = new ByteString("87"+L87+Pi+msgEncriptado,HEX);
//lanzar inquire
var vectorIMac = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX)).add(1);
var inqTLV = new ByteString("89 04 8C E4 02 00",HEX);
var MacClaro = inqTLV.concat(TLV87);
var MacRelleno = MacClaro.pad(Crypto.ISO9797_METHOD_2, true);
var MacCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacRelleno, vectorIMac);
print("paso 4");
var todoCifrado = MacCifrado.right(8);
var Mac4 = todoCifrado.left(4);

//enviar
var resp = card.plainApdu(new ByteString("8C E4 02 00" + (9 + msgEncriptado.length).toString(16),HEX).concat(TLV87).concat(new ByteString("8E 04", HEX)).concat(Mac4));
print("Código SW: " + card.SW.toString(16));

//Get Response
print("");
autenticacion = card.plainApdu(new ByteString("80 C0 00 00 17", HEX));
print ("Respuesta a la autenticación " + autenticacion);
print("Código SW: " + card.SW.toString(16));
//verificar MAC
//verificar MAC
var vectorIMac2 = aleatorioC.and(new ByteString("00 00 00 00 00 00 FF FF",HEX)).add(2);
var vectorIMac3 = vectorIMac2.add(1);//credit
var vectorIMac4 = vectorIMac3.add(1);//inquire despues de credit
var vectorIMac5 = vectorIMac4.add(1);//get response despues de inquire

var respuestaConc = inqTLV.concat(autenticacion.left(autenticacion.length - 6));
var MacComprobarRelleno = respuestaConc.pad(Crypto.ISO9797_METHOD_2, true);
var MacComprobarCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacComprobarRelleno, vectorIMac2);
var todoCifrado = MacComprobarCifrado.right(8);
var Mac4 = todoCifrado.left(4);


print("Comprobar coincidencia MAC: "+autenticacion.right(4)+"+<------>"+Mac4);

if(autenticacion != ""){
	print("la tarjeta se ha autenticado correctamente: "+autenticacion);
	//Lanzar inquire con los datos obtenidos
	var resulL  = autenticacion.bytes(1,1).toSigned()-1;
    var resulPi = autenticacion.bytes(2,1);
    
    //desciframos el resultado de la autenticación
    var resulDescifrado = crypto.decrypt(deskey, Crypto.DES_CBC, autenticacion.bytes(3,resulL), vectorIMac2);
    
   
    monedero = resulDescifrado.bytes(0,resulL - resulPi.toSigned());
    monedero = monedero.bytes(4);
    print("Balance pre operacion: "+monedero.bytes(1,3).toSigned());
    
    //realizamos la operacion de debit con 12,50e
    //lanzar DEBIT 12,50e --> 1250 unidades
	var ingreso = new ByteString("00 04 E2",HEX);
	var Balance = monedero.bytes(1,3);
    var ATREF = monedero.bytes(4,6);
	var ATREF2 = ATREF.add(1);
	var TTREFC = monedero.bytes(13,4);
	var TTREFD = monedero.right(4);
	var MacCredit = new ByteString("E6",HEX).concat(ingreso).concat(TTREFD).concat(ATREF2).concat(new ByteString("00 00",HEX));
	deskey.setComponent(Key.DES, Kd);
	var VI = new ByteString("00 00 00 00 00 00 00 00", HEX);
	calcularMacCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacCredit, VI);
	todoCifrado = calcularMacCifrado.right(8);
	var Mac4Credit = todoCifrado.left(4);
	print(" Mac4Credit: "+Mac4Credit);
	
	//estructurar datos
	
	deskey.setComponent(Key.DES, Ks);
	var credito = Mac4Credit.concat(ingreso).concat(TTREFC);
	var creditoRelleno = credito.pad(Crypto.ISO9797_METHOD_2);
	var creditoCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, creditoRelleno, vectorIMac3);
	
	var TLV87 = "87";
	var L87 =  (creditoCifrado.length+1).toString(16);
	print ("L87: ", L87)
	var Pi87 = "0" + (credito.pad(Crypto.ISO9797_METHOD_2).length - credito.length).toString(16);
	print ("pi: ", Pi87)

	//Pasos para evitar la malformación de la petición, version 3
	var TLV87 = new ByteString(TLV87+L87+Pi87,HEX).concat(creditoCifrado);
	print ("TLV87: ", TLV87.toString())
	var TLVDeb = new ByteString("89 04 8C E6 00 00",HEX);
	TLVCred = TLVDeb.concat(TLV87);
	
	var TLVCredrelleno = TLVCred.pad(Crypto.ISO9797_METHOD_2, true);
	
	var TLVCredCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, TLVCredrelleno, vectorIMac3);
	
	var MACcredit = TLVCredCifrado.right(8).left(4);
	var isoIn = new ByteString((9 + creditoCifrado.length).toString(16),HEX);
	print ("Pre debit SM: " + new ByteString("8C E6 00 00",HEX).concat(isoIn).concat(TLV87).concat(new ByteString("8E 04", HEX)).concat(MACcredit));
	var resp = card.plainApdu(new ByteString("8C E6 00 00",HEX).concat(isoIn).concat(TLV87).concat(new ByteString("8E 04", HEX)).concat(MACcredit));
	print ("Respuesta debit SM" + resp);
	print("Código SW: " + card.SW.toString(16));
    //Get Response
	print("");
	autenticacion = card.plainApdu(new ByteString("80 C0 00 00 0C", HEX));
	print ("Respuesta a la autenticación " + autenticacion);
	print("Código SW: " + card.SW.toString(16));
	
	
	if(autenticacion != ""){
		var respuestaConc = TLVDeb.concat(autenticacion.left(4));
		var MacComprobarRelleno = respuestaConc.pad(Crypto.ISO9797_METHOD_2, true);
		var MacComprobarCifrado = crypto.encrypt(deskey, Crypto.DES_CBC,MacComprobarRelleno, vectorIMac4);
		var todoCifrado = MacComprobarCifrado.right(8);
		var Mac5 = todoCifrado.left(4);
		print("Comprobar coincidencia MAC 2: "+autenticacion.right(4)+"+<------>"+Mac5);
	}
	load("inquireSecure.js");
}