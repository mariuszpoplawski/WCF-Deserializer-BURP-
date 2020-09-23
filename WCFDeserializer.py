# -*- coding: utf-8 -*-
"""
WCFDeserializer Burp Plugin v1.0

Works without external ".exe", requires jython.
Tested on macOS and Windows 10 with Burp 2020.9.1
#  WCFDeserializer Copyright (c) 2020, Maciej Domański <mddomanski@afine.com> and Mariusz Popławski <mpoplawski@afine.com> (afine.pl team)

#  WCF Library Copyright (c) 2011, Timo Schmid <tschmid@ernw.de>

Credits to Anthony Marquez for initial version that i edited

#  All rights reserved.
"""

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from java.io import PrintWriter
from StringIO import StringIO
from wcf.records import Record,print_records
from wcf.xml2records import XMLParser
from wcf.records import dump_records
import traceback

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WCFDeserializer")
        callbacks.registerMessageEditorTabFactory(self)
        return

    def createNewInstance(self, controller, editable):
        return WCFDeserializer(self, controller, editable)


class WCFDeserializer(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.editable = editable
        self.controller = controller

        self.txtInput = extender.callbacks.createTextEditor()
        self.txtInput.setEditable(editable)

        self.httpHeaders = None
        self.body = None
        self.content = None
        return

    def getTabCaption(self):
        return "WCFDeserializer"

    def getUiComponent(self):
        return self.txtInput.getComponent()

    def isModified(self):
        return self.txtInput.isTextModified()

    def getSelectedData(self):
        return self.txtInput.getSelectedText()

    def getHeadersContaining(self, findValue, headers):
        if findValue is not None and headers is not None and len(headers) > 0:
            return [s for s in headers if findValue in s.lower()]
        return None

    def isEnabled(self, content, isRequest):
        #Content-Type: contains msbin1
        self.content = content
        request_or_response_info = None
        if isRequest:
            request_or_response_info = self.extender.helpers.analyzeRequest(content)
        else:
            request_or_response_info = self.extender.helpers.analyzeResponse(content)
        if request_or_response_info is not None:
            headers = request_or_response_info.getHeaders()
            if headers is not None and len(headers) > 0:
                self.httpHeaders = headers
                self.body = self.extender.helpers.bytesToString(content[request_or_response_info.getBodyOffset():])
                matched_headers = self.getHeadersContaining('content-type', headers)
                if matched_headers is not None:
                    for matched_header in matched_headers:
                        if 'msbin1' in matched_header:
                            return True

        return False

    def getPrettyXML(self,xmldata):
        try:
            return minidom.parseString(xmldata).toprettyxml(encoding="utf-8")
        except:
            return xmldata


    def decodeWCF(self, binaryString):
        try:
            fp = StringIO(binaryString)
            data = Record.parse(fp)
            fp.close()
            fp = StringIO()
            print_records(data, fp=fp) 
            data = fp.getvalue()
            fp.close()
            return data
        except ValueError:
            tb = traceback.format_exc()
            return tb

    def encodeWCF(self, data):

        try:


            #data = dump_records(XMLParser.parse(self.extender.helpers.bytesToString(data)))
            
            fp = StringIO(self.extender.helpers.bytesToString(data))
            data = fp.getvalue()
            out = dump_records(XMLParser.parse(str(data)))

            return out

        except ValueError:
            tb = traceback.format_exc()
            return tb

        return "0"

        try:
            XML = self.extender.helpers.bytesToString(data)
            #XML = XML.replace("\n", '').replace("\t", '')
            parsedXML = XMLParser.parse(str(XML))
            serializedXml = dump_records(parsedXML)
            return serializedXml
        except ValueError:
            tb = traceback.format_exc()
            return tb

    def setMessage(self, content, isRequest):
        self.txtInput.setText(self.decodeWCF(self.body))
        return

    def getMessage(self):
        if self.txtInput.isTextModified():
            encoded_txt = self.txtInput.getText()
            return self.extender.helpers.buildHttpMessage(self.httpHeaders, self.encodeWCF(encoded_txt))
        else:
            return self.content
