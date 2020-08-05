from signxml import XMLSigner
from lxml import etree
import datetime
import StringIO
import base64
import zlib




SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

XML_TEMPLATE = '''
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%(acs_url)s" ID="%(generated_id)s" InResponseTo="%(responsetoid)s" IssueInstant="%(timenow)s" Version="2.0">
   <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%(issuer)s</saml:Issuer>
   <samlp:Status>
       <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
   </samlp:Status>
   <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%(generated_assertion_id)s" IssueInstant="%(timenow)s" Version="2.0">
       <saml:Issuer>%(issuer)s</saml:Issuer>
       <saml:Subject>
           <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="%(sp_name)s">%(name_id)s</saml:NameID>
           <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
               <saml:SubjectConfirmationData InResponseTo="%(responsetoid)s" NotOnOrAfter="%(expirytime)s" Recipient="%(acs_url)s"/>
           </saml:SubjectConfirmation>
       </saml:Subject>
       <saml:Conditions NotBefore="%(timenow)s" NotOnOrAfter="%(expirytime)s">
           <saml:AudienceRestriction>
               <saml:Audience>%(audience)s</saml:Audience>
           </saml:AudienceRestriction>
       </saml:Conditions>
       <saml:AuthnStatement AuthnInstant="%(timenow)s">
           <saml:AuthnContext>
               <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
           </saml:AuthnContext>
       </saml:AuthnStatement>
   </saml:Assertion>
</samlp:Response>

'''
#       <saml:AttributeStatement></saml:AttributeStatement>





class samuelIDP(object):
    def __init__(self,file_cert=None,file_key=None):
        self.__pfc = file_cert;
        self.__pfk = file_key;

    @staticmethod
    def decode_base64_and_inflate(b64string):
        decoded_data = base64.b64decode(b64string)
        # return zlib.decompress( decoded_data.encode('utf-8') , -15)
        return zlib.decompress(decoded_data, -15)


    @property
    def pemkey(self):
        pFile = open(self.__pfk);
        rVal = pFile.read();
        pFile.close();
        return rVal;
    @property
    def pemcert(self):
        pFile = open(self.__pfc);
        rVal = pFile.read();
        pFile.close();
        return rVal;



    def __canonicalize(self,xml_str):
        parser = etree.XMLParser(remove_blank_text=True)
        string = StringIO.StringIO();
        tree = etree.fromstring(xml_str,parser=parser).getroottree();
        tree.write_c14n(string, exclusive=True, with_comments=False);
        return string.getvalue();

    def __reorder_signature(self,tree):
        sig = tree.getchildren()[-1];
        tree.insert(1,sig);

    def genAuthnResponse(self,responsetoid, acs_url, issuer, name_id=""):
        cert_pem = self.pemcert;
        key_pem = self.pemkey;


        format = {
            "timenow": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generated_id": "_92c76e8d097344229ba1b13200f15fe6",
            "generated_assertion_id": "_f2bee8431dda412c90ac584a5afa342d",
            "expirytime": (datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "acs_url": acs_url,
            "issuer": issuer,
            "responsetoid": responsetoid,
            "name_id": name_id,
            "sp_name": acs_url.split('/')[2][4:],  # tamad: derive qualified SP name from acs_url
            "audience" : acs_url.split('/')[2][4:]  # tamad: derive audience name from acs_url
        }

        tree = etree.fromstring(self.__canonicalize(XML_TEMPLATE % format));
        assertion_tree = tree.find("{%s}Assertion" % SAML_ASSERTION_NS);
        signed_assertion_tree = XMLSigner(signature_algorithm='rsa-sha1', digest_algorithm='sha1', c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#').sign(assertion_tree,
                                                                                                        key=key_pem,
                                                                                                        cert=cert_pem);
        self.__reorder_signature(signed_assertion_tree);

        # awkward replacement
        tree.remove(assertion_tree);
        tree.append(signed_assertion_tree);

        # return etree.tostring(XMLSigner(signature_algorithm='rsa-sha1',digest_algorithm='sha1').sign(tree,key=pemkey,cert=pemcert));
        treeRes = XMLSigner(signature_algorithm='rsa-sha1', digest_algorithm='sha1', c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#').sign(tree, key=key_pem, cert=cert_pem);
        self.__reorder_signature(treeRes);
        #rVal = etree.tostring(treeRes);
        return self.__canonicalize(etree.tostring(treeRes));

    def getParametersFromAuthnRequest(self,b64xmlstr):
        xml_str = samuelIDP.decode_base64_and_inflate(b64xmlstr);

        tree = etree.fromstring(xml_str);
        ID = tree.attrib['ID'];
        ACS_URL = tree.attrib['AssertionConsumerServiceURL'];
        assertion_tree = tree.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer");
        if not assertion_tree:
            return None;
        ISSUER = assertion_tree.text.strip();

        #memory pls
        assertion_tree.clear();
        del assertion_tree;
        tree.clear();
        del tree;

        return (ID,ACS_URL,ISSUER);




