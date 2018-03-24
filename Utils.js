function SelectHex(position){
	var sel = "80 A4 00 00 02";
	return sel.concat(position);
}

function WriteHex(RecIn,Offset,Length,Data){
  var write = "80 D2";
  return write.concat(RecIn,Offset,Length,Data);
 }