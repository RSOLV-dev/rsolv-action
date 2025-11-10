/**
 * Test detection on actual minified RailsGoat line 737
 */

const apiPattern = {
  id: 'js-eval-user-input',
  regex: '^(?!.*//).*eval\\s*\\(.*?(?:req\\.|request\\.|params\\.|query\\.|body\\.|user|input|data|Code)'
};

// Actual line 737 from RailsGoat (truncated to relevant part)
const line737 = `function sh_load(language,element,prefix,suffix){if(language in sh_requests){sh_requests[language].push(element);return}sh_requests[language]=[element];var request=sh_getXMLHttpRequest();var url=prefix+"sh_"+language+suffix;request.open("GET",url,true);request.onreadystatechange=function(){if(request.readyState===4){try{if(!request.status||request.status===200){eval(request.responseText);var elements=sh_requests[language];for(var i=0;i<elements.length;i++){sh_highlightElement(elements[i],sh_languages[language])}}else{throw"HTTP error: status "+request.status}}finally{request=null}}};request.send(null)}`;

console.log('Testing minified line 737 from RailsGoat');
console.log('Line length:', line737.length);
console.log('Contains eval(request.responseText):', line737.includes('eval(request.responseText)'));

// Create regex as action would
const regex = new RegExp(apiPattern.regex, 'im');
console.log('\nRegex:', regex);

// Test
const matches = regex.test(line737);
console.log('\nRegex test result:', matches ? '✓ MATCH' : '✗ NO MATCH');

if (matches) {
  const match = regex.exec(line737);
  console.log('Match found:', match[0]);
  console.log('Match index:', match.index);
}
