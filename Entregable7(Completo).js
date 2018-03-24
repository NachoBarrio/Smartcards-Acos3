card = new Card();
atr = card.reset(Card.RESET_COLD);
//print(atr);
print("");
var string8DC1 = new ByteString("8DC1 Ignacio Barrio Santos MASTER DE SISTEMAS Aplicaciones para Smart Cards 2017 2018 8DC1 En un lugar de la mancha de cuyo nombre no quiero acordarme",ASCII);
var string8DC2 = new ByteString("8DC2 Ignacio Barrio Santos MASTER DE SISTEMAS Aplicaciones para Smart Cards 2017 2018 8DC2 En un lugar de la mancha de cuyo nombre no quiero acordarme",ASCII);
var string8DC3 = new ByteString("8DC3 Ignacio Barrio Santos MASTER DE SISTEMAS Aplicaciones para Smart Cards 2017 2018 8DC3 En un lugar de la mancha de cuyo nombre no quiero acordarme",ASCII);
var string8DC4 = new ByteString("8DC4 Ignacio Barrio Santos MASTER DE SISTEMAS Aplicaciones para Smart Cards 2017 2018 8DC4 En un lugar de la mancha de cuyo nombre no quiero acordarme",ASCII);

print("          FICHERO USER FILE MANAGEMENT FF04");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8DC1", HEX));
print("");

print("Escribir en fichero 8DC1");
var escribirBin = "80 D0";
resp = card.plainApdu(new ByteString(escribirBin.concat("00 00", string8DC1.length.toString(16)), HEX).concat(string8DC1));
print("Código SW: " + card.SW.toString(16));

print("Escribir en fichero 8DC2");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C2", HEX));

resp = card.plainApdu(new ByteString(escribirBin.concat("00 00", string8DC2.length.toString(16)), HEX).concat(string8DC2));
print("Código SW: " + card.SW.toString(16));

print("Escribir en fichero 8DC3");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C3", HEX));
//truncar total records tamaño record por bytes 2032
	//TO DO
var i = 0;
var posNum = 0;
do{
	if(posicion < 16){
	 posicion = "0" + posNum.toString(16);
	}else{
	 posicion = posNum.toString(16);
	}

	if(string8DC3.length - i >= 16){
	 
		card.plainApdu(new ByteString("80 D2 "+posicion+" 00 10 "+string8DC3.bytes(i,16),HEX));
	}else{
		card.plainApdu(new ByteString("80 D2 "+posicion+" 00 0"+(string8DC3.length - i).toString(16)+" "+string8DC3.bytes(i,string8DC3.length - i),HEX));
	}
 posNum++;
 i = i + 16;
}while(i < string8DC3.length)
print("Código SW: " + card.SW.toString(16));

print("Escribir en fichero 8DC4");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 8D C4", HEX));
//truncar total records tamaño record por bytes 16320
var i = 0;
var posNum = 0;
do{
	if(posicion < 16){
	 posicion = "0" + posNum.toString(16);
	}else{
	 posicion = posNum.toString(16);
	}

	if(string8DC4.length - i >= 64){
	print(i+","+posicion+","+posNum);
		card.plainApdu(new ByteString("80 D2 "+posicion+" 00 40 "+string8DC4.bytes(i,64),HEX));
	}else{
	print(string8DC4.length+","+i+","+posicion+","+posNum);
		if(string8DC3.length - i < 16){
			card.plainApdu(new ByteString("80 D2 "+posicion+" 00 0"+(string8DC4.length - i).toString(16)+" "+string8DC4.bytes(i,string8DC4.length - i),HEX));
		}else{
			card.plainApdu(new ByteString("80 D2 "+posicion+" 00 "+(string8DC4.length - i).toString(16)+" "+string8DC4.bytes(i,string8DC4.length - i),HEX));
		}
	}
 posNum++;
 i = i + 64;
}while(i < string8DC4.length)
print("Código SW: " + card.SW.toString(16));