
# PESD Wrapper - Methods Detail
**Note**: If a method's signature contains the *Integer index* parameter, it is optional. If specified in the call, its value is used as an index within the data array when performing the method's action. Otherwise, the current iterator index value is used.<br><br>

| Return Type  | Method's Signature and Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| -            | **PESDWrapper(PrintWriter stdout)**<br>  main constructor                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| -            | **PESDWrapper(PrintWriter stdout, JSONArray data)**<br>  Constructor usable to create copies of a PESD Object, simply use *getStucturedData()* to extract JSONArray data and pass it to the constructor                                                                                                                                                                                                                                                                                        |
| *String*     | **getSeqDiagramdMD(Integer op_mode)**<br>  This method serializes the JSONArray data to MermaidJS Markdown syntax.  The *op_mode* parameter indicates the export mode:  - 0 = Domains as Actors  - 1 = Endpoints as Actors  Returns a string containing a valid MermaidJS Markdown Sequence Diagram                                                                                                                                                                                              |
| *JSONObject* | **getMetadata()**<br>  Generates the metadata export with PESD format                                                                                                                                                                                                                                                                                                                                                                                                                            |
| *JSONObject* | **getLine(*Integer index*)**<br> Returns line at *index*; If no parameter is passed, returns line according to the internal iterator                                                                                                                                                                                                                                                                                                                                                                 |
| *Integer*    | **getIterator()**<br> Returns the current index value of the internal iterator. Return -1 if the end of the object is reached                                                                                                                                                                                                                                                                                                                                                                                                                 |
| *void*       | **setIterator()**<br> Set index value of the internal iterator to 0                                                                                                                                                                                                                                                                                                                                                                                                                              |
| *void*       | **startIterator(Integer num)**<br> Set index value of the internal iterator to *num* parameter                                                                                                                                                                                                                                                                                                                                                                                                   |
| *void*       | **nextLine()**<br> Increase the internal iterator index by 1                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| *void*       | **prevLine()**<br> Decrease the internal iterator index by 1                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| *void*       | **addReq(String source, String destination, String method, String path, List flags, JSONObject metadata, *Integer index*)**<br>  Method used to add a Request line to the obj that will have the format:  Markdown :  S ->> D : [METHOD] /path \n Flag1 Flag2 ... FlagN   Metadata: JSONObject generated by PESDMetadata obj                    |
| *void*       | **addRes(String source, String destination, String status_code, String mimeType,List flags, JSONObject metadata, *Integer index*)**<br>  Method used to add a Response line to the obj that will have the format:  Markdown :  D ->> S : [STATUS_CODE] MIME_TYPE \n Flag1 Flag2 ... FlagN   Metadata: JSONObject generated by PESDMetadata obj  |
| *void*       | **addAlt(String text, *Integer index*)**<br>  Method used to add an Alt line (rectangle start in MermaidJS MD) to the obj that will have the format :   Markdown :  Alt NAME                                                                                                                                                                     |
| *void*       | **endAlt(*Integer index*)**<br>  Method used to add an end line (rectangle close in MermaidJS MD) to the obj that will have the format :   Markdown :  end                                                                                                                                                                                       |
| *void*       | **addNote(String note, *Integer index*)**<br>  Method used to add a Note line to the obj that will have the format:   Markdown :  Note right of Browser : TEXT                                                                                                                                                                                  |
| *void*       | **modifyFlags(List flagsArr, *Integer index*)**<br>  Substituting flags in a transaction during an iteration.                                                                                                                                                                                                                                   |
| *void*       | **addFlag(String flag, *Integer index*)**<br>  Adding a flag to a transaction while iterating.                                                                                                                                                                                                                                                  |
| *void*       | **modifyMetadata(JSONObject metadataObj, *Integer index*)**<br>  Replacing a metadata object in a line with new metadata while iterating.                                                                                                                                                                                                       |
| *void*       | **removeLine(*Integer index*)**<br>  Remove line while iterating                                                                                                                                                                                                                                                                                |
| *Boolean*    | **altEndConsistencyNormalizer()**<br>  This method is used to resolve local consistency problems within the resulting MermaidJS Markdown before the serialization.  Currently, it simply removes non-closed and non-opened Alt rectangles (Alt without end or end without Alt). Moreover, in case of 2 consecutive Alt, the first occurrence is removed                                                                                                                                        |
| *void*       | **addToPos(int pos, JSONObject jsonObj)**<br>  Function needed to perform JSONArray.put(pos, json) without losing an entry due to replacement.  Basically it performs right-shift of all the entries after the position needed for the put                                                                                                                                                                                                                                                       |
| *Integer*    | **getSize()** <br> Return the number of lines within the Sequence Diagram                                                                                                                                                                                                                                                                                                                                                                                                                        |
| *JSONArray*  | **getStucturedData()**<br> Return a copy by value of the data contained in the wrapper                                                                                                                                                                                                                                                                                                                                                                                                           |




### Internal Data Structure
The internal data structure :
```
[
	{
	"type": "req",
	"source": *String*,
	"destination": *String*,
	"maskedPath": *String*,
	"method": *String*,
	"path": *String*,
	"flags": *List<String>*,
	"metadata": *JSONObject*
	},
	{
	"type": "res",
	"source": String,
	"destination": String,
	"status_code": String,
	"mime_type": String,
	"flags": List<String>,
	"metadata": JSONObject
	},
	{
	"type": "alt",
	"alt": String,
	},
	{
	"type": "end"
	},
	{
	"type": "Note",
	"note": String,
	},
.
.
.

]
```

### Usage Examples
```
PESDWrapper pesdObj = new PESDWrapper(out_printWriter);
// Generic function that fills the object
fill_PESD(pesdObj);
// Setting the internal iterator to 0
pesdObj.startIterator();
// Iterating until we get end of PESD from *getIterator* (-1)
while (pesdObj.getIterator() != -1) {
	// Getting current line according to internal iterator
	JSONObject line = pesdObj.getLine();
	// Switching actions depending on the type of line
	switch((String) line.get("type")){
		case "req": 
			// do stuff
		case "res":
			// do stuff
		default: break
	}
	// Classic i++
	pesdObj.nextLine();
}
```
