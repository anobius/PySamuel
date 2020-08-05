from signxml import XMLVerifier
from lxml import etree
import string
import random
import zlib
import base64
import datetime

###logging
import logging
logger = logging.getLogger('samlSP')
__handler = logging.StreamHandler()
__formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s","%Y-%m-%d %H:%M:%S")
__handler.setFormatter(__formatter)
__handler.setLevel(logging.DEBUG)
logger.addHandler(__handler)
###

XMLNS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
XMLNS_SAMLASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";



AUTHNREQUEST_TEMPLATE = '''<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    ID="%(ID)s"
    Version="2.0"
    IssueInstant="%(ISSUE_TIME)s"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    ProviderName="%(PROVIDER)s"
    IsPassive="false"
    AssertionConsumerServiceURL="%(ACS_URL)s">
    <saml:Issuer
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%(ISSUER)s
    </saml:Issuer>
    <samlp:NameIDPolicy
        AllowCreate="true"
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />
</samlp:AuthnRequest>'''




def decode_base64_and_inflate( b64string ):
    decoded_data = base64.b64decode( b64string )
    #return zlib.decompress( decoded_data.encode('utf-8') , -15)
    return zlib.decompress( decoded_data , -15)

def deflate_and_base64_encode( string_val ):
    zlibbed_str = zlib.compress( string_val.encode('utf-8') )
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode( compressed_string )

def gen_id(size=32, chars=string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size));


class samuelSPAuthProcessor(object):

    def __init__(self,certpem,auth_endpoint_url,provider_name,issuer):
        '''
        Create an SP Processor object
        :param certpem: PEM text string of the certificate
        :param auth_endpoint_url: IDP Authentication URL
        :param provider_name: todo: description
        :param issuer: todo: description
        '''
        self._endpoint = auth_endpoint_url;
        self.__publiccert = certpem;
        self.__provider = provider_name;
        self.__issuer = issuer;


    def validateAuthnResponse(self,xml_string,**kwargs):
        '''
        Verifies only the Assertion segment of the XML, returns the Assertion tree if successful, none otherwise
        :param xml_string:
        :param kwargs:
        :return: assertion lxml tree
        '''
        root = etree.fromstring(xml_string);


        assertion = root.find('{%s}Assertion' % XMLNS_SAMLASSERTION);

        subject = assertion.find("{%s}Subject" % XMLNS_SAMLASSERTION);
        if subject is None:
            logger.critical("Received AuthnResponse with missing subject!")
            return ;
        user = subject.find("{%s}NameID" % XMLNS_SAMLASSERTION).text;

        conditions = assertion.find('{%s}Conditions' % XMLNS_SAMLASSERTION);
        if conditions is None:
            logger.critical("Received assertion with no conditions! Subject was \"%s\"" % user);
            return ;

        assertionExpiry = datetime.datetime.strptime(conditions.attrib['NotOnOrAfter'],"%Y-%m-%dT%H:%M:%SZ");
        assertionManufactory = datetime.datetime.strptime(conditions.attrib['NotBefore'],"%Y-%m-%dT%H:%M:%SZ");
        currentTimeUTC = datetime.datetime.utcnow();
        if not ((currentTimeUTC < assertionExpiry) and (currentTimeUTC >= assertionManufactory)):
            logger.critical("Assertion is already invalid for the current time! Subject was \"%s\"" % user);
            return ;
        #todo: check audience restriction
        #todo: saml-schema-protocol-2.0.xsd checking ..?
        try:
            return XMLVerifier().verify(assertion,x509_cert=self.__publiccert).signed_xml;
        except Exception as e:
            logger.warning("Assertion signature validation failed: %s; Subject was \"%s\"" % (e,user));
            return ;

    def genAuthnRequest(self,acs_url):
        '''
        Generate a SAML Authn Request
        :param acs_url: Callback URL for the IDP
        :return: Base64 encoded, deflated SAML Request
        '''
        id = gen_id();

        tokens = dict();
        tokens['ID'] = id;
        tokens['PROVIDER'] = self.__provider;
        tokens['ISSUER'] = self.__issuer;
        tokens['ACS_URL'] = acs_url;
        tokens['ISSUE_TIME'] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ");
        return deflate_and_base64_encode(AUTHNREQUEST_TEMPLATE % tokens);

    def decodeAndValidate(self, samlResponse):
        '''
        Decodes and Validates. yes. :)
        :param samlResponse: raw SAML Response
        :return: assertion lxml tree
        '''
        decoded_data = base64.b64decode(samlResponse)
        validated_data = self.validateAuthnResponse(decoded_data)

        return validated_data



class samuelSP(samuelSPAuthProcessor):
    def getName(self,verified_assertion_xml):
        '''
        Returns the NameID section specified in the Subject section
        :param verified_assertion_xml: validated xml string of the assertion
        :return: string value of the NameID if exists
        '''
        userid = verified_assertion_xml.find("{%s}Subject" % XMLNS_SAMLASSERTION);
        if userid:
            return userid.find("{%s}NameID" % XMLNS_SAMLASSERTION).text;


    def getAttributeList(self,verified_assertion_xml):
        '''
        Returns the attributes specified in the Assertion
        :param verified_assertion_xml: validated xml string of the assertion
        :return: dictionary of attributes: { attributename : value }
        '''
        attributestatement = verified_assertion_xml.find("{%s}AttributeStatement" % XMLNS_SAMLASSERTION);

        rVal = dict();
        if attributestatement:
            attributelist = attributestatement.findall("{%s}Attribute" % XMLNS_SAMLASSERTION);

            for i in attributelist:
                pKey = i.attrib['Name'];
                value = list(i)[0].text.strip()
                checkvalue = value.lower();
                rVal[pKey] = True if checkvalue == "true" else False if checkvalue == "false" else value;

        return rVal;

    def getAuthEndpoint(self):
        return self._endpoint;
