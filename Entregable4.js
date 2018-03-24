card = new Card();
atr = card.reset(Card.RESET_COLD);
//print(atr);

//sacar información F1
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C1", HEX));
print("Código SW: " + card.SW.toString(16));
print("");
resp = card.plainApdu(new ByteString("80 B0 00 00 00", HEX));
print("Código SW: " + card.SW.toString(16));
print("");
print("resp: "+resp);
print ("F1: " + resp.toString(ASCII));

//sacar información F2
var fichero = "";
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C2", HEX));

resp = card.plainApdu(new ByteString("80 B0 00 00 00", HEX));
fichero = fichero.concat(resp.toString(ASCII));
resp = card.plainApdu(new ByteString("80 B0 01 00 00", HEX));
fichero = fichero.concat(resp.toString(ASCII));
resp = card.plainApdu(new ByteString("80 B0 02 00 00", HEX));
fichero = fichero.concat(resp.toString(ASCII));
resp = card.plainApdu(new ByteString("80 B0 03 00 00", HEX));
fichero = fichero.concat(resp.toString(ASCII));
print ("F2: " + fichero);

//sacar información F3 --> ojo binario TO DO
 fichero = "";
 resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C3", HEX));
 print("Código SW: " + card.SW.toString(16));
print("");
fichero = fichero.concat(resp.toString(ASCII));
for(var i = 0;i <= 126; i++){
	if( i < 16){
	  resp = card.plainApdu(new ByteString("80 B2 0"+i.toString(16)+" 00 10", HEX));
	  fichero = fichero.concat(resp.toString(ASCII));
	}else{
		resp = card.plainApdu(new ByteString("80 B2 "+i.toString(16)+" 00 10", HEX));
		fichero = fichero.concat(resp.toString(ASCII));
	}
	
}
print ("F3: " + fichero);


//sacar información F4 
 fichero = "";
 resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C4", HEX));
 print("Código SW: " + card.SW.toString(16));
print("");
fichero.concat(resp.toString(ASCII));
for(var i = 0;i <= 254; i++){
	if( i < 16){
	  resp = card.plainApdu(new ByteString("80 B2 0"+i.toString(16)+" 00 40", HEX));
	  fichero = fichero.concat(resp.toString(ASCII));
	}else{
		resp = card.plainApdu(new ByteString("80 B2 "+i.toString(16)+" 00 40", HEX));
		fichero = fichero.concat(resp.toString(ASCII));
	}
	
}
print ("F4: " + fichero);