//-----------------------------------------------------------------------------
// FUNCIONES Y GLOBALES

//Adapt to read only

selectApdu = "80 A4";
readRecordApdu  = "80 B2";
readBinaryApdu  = "80 B0";

f1Id = "8DC1";
f2Id = "8DC2";
r1Id = "8DC3";
r2Id = "8DC4";


card = new Card();
atr = card.reset(Card.RESET_COLD);

card.plainApdu(new ByteString(selectApdu.concat("00 00 02", f1Id), HEX));
if ( card.SW.toString(16) == "9100")
{
  print("-x-x-x-x-x-x-x-x-x-----reading file 1-----x-x-x-x-x-x-x-x-x-");
  {
  	resp = card.plainApdu(new ByteString(readBinaryApdu.concat("00 00 00"), HEX));
  	print ("content: " + resp);
  	print ("in text: " + resp.toString(ASCII));
  }
}

card.plainApdu(new ByteString(selectApdu.concat("00 00 02", f2Id), HEX));
if ( card.SW.toString(16) == "9101")
{
  print("-x-x-x-x-x-x-x-x-x-----reading file 2-----x-x-x-x-x-x-x-x-x-");
  resp = new ByteString("", HEX);
  resp = resp.concat(card.plainApdu(new ByteString(readBinaryApdu.concat("00 00 00"), HEX)));
  resp = resp.concat(card.plainApdu(new ByteString(readBinaryApdu.concat("01 00 00"), HEX)));
  resp = resp.concat(card.plainApdu(new ByteString(readBinaryApdu.concat("02 00 00"), HEX)));
  resp = resp.concat(card.plainApdu(new ByteString(readBinaryApdu.concat("03 00 00"), HEX)));
  print ("content: " + resp);
  print ("in text: " + resp.toString(ASCII));
  //else
}

card.plainApdu(new ByteString(selectApdu.concat("00 00 02", r1Id), HEX));
if ( card.SW.toString(16) == "9102")
{
  print("-x-x-x-x-x-x-x-x-x-----reading file 3-----x-x-x-x-x-x-x-x-x-");
  resp = new ByteString("", HEX);
  for (var i = 0; i <= 126; i++) 
  {
	hex=i.toString(16);
	hex.length < 2 ? hex = "0" + hex : hex = hex;
	resp = resp.concat(card.plainApdu(new ByteString("80 B2 "+hex+" 00 10", HEX)));
  }
  print ("content: " + resp);
  print ("in text: " + resp.toString(ASCII));
}

card.plainApdu(new ByteString(selectApdu.concat("00 00 02", r2Id), HEX));
if ( card.SW.toString(16) == "9103")
{
  print("-x-x-x-x-x-x-x-x-x-----reading file 4-----x-x-x-x-x-x-x-x-x-");
  resp = new ByteString("", HEX);
  for (var i = 0; i <= 254; i++) 
  {
	hex=i.toString(16);
	hex.length < 2 ? hex = "0" + hex : hex = hex;
	resp = resp.concat(card.plainApdu(new ByteString("80 B2 "+hex+" 00 40", HEX)));
  }
  print ("content: " + resp);
  print ("in text: " + resp.toString(ASCII));
}
