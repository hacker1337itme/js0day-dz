# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IHttpListener
from javax.swing import JTable, JScrollPane, JFrame, JButton
from javax.swing.table import DefaultTableModel
import re
from java.awt.event import WindowAdapter

class BurpExtender(IBurpExtender, IHttpListener):
    def __init__(self):
        self.functions_with_links = []  # List to store JavaScript functions and their links
        self.js_sinks_with_links = []    # List to store JavaScript sinks and their links
        self.js_links = []                # List to store JavaScript links

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set the name of the extension
        callbacks.setExtensionName("JS Function and Sink Extractor [JS0DAY-DZ]")

        # Register the HTTP listener
        callbacks.registerHttpListener(self)

        # Create the GUI
        self.create_gui()

        # Fetch existing functions and sinks from sitemap
        self.fetch_links_from_sitemap()

    def create_gui(self):
        # Create the main frame
        self.frame = JFrame("JavaScript Functions and Sinks BY EL-HA9")
        self.frame.setSize(600, 400)

        # Prevent the application from closing when the GUI is closed
        self.frame.addWindowListener(ClassWindowAdapter(self))
        self.frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE)

        # Create table model and table
        self.model = DefaultTableModel(["Function/Sink Name", "Link"], 0)
        self.table = JTable(self.model)

        # Add components to the frame
        self.frame.getContentPane().add(JScrollPane(self.table))

        refresh_button = JButton("Refresh", actionPerformed=self.refresh_table)
        self.frame.getContentPane().add(refresh_button, "South")

        # Enable the GUI
        self.frame.setVisible(True)

    def refresh_table(self, event):
        # Clear the current model
        self.model.setRowCount(0)
        for function, link in self.functions_with_links:
            self.model.addRow([function, link])
        for sink, link in self.js_sinks_with_links:
            self.model.addRow([sink, link])

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response is not None:
                responseStr = self._helpers.bytesToString(response)

                # Extract JavaScript functions and sinks
                self.extract_js_and_sinks(responseStr, messageInfo.getUrl().toString())

                # Fetch new links from the response body
                self.extract_new_links(responseStr)

                # If there are JS links, fetch and process them
                self.fetch_and_extract_functions_and_sinks_from_links()

    def extract_js_and_sinks(self, responseStr, base_url):
        # Extract JavaScript links (src in script tags)
        js_link_pattern = r'<script[^>]+src="([^"]+)"'
        js_links_found = re.findall(js_link_pattern, responseStr)
        self.js_links.extend(js_links_found)

        # Extract functions from the JavaScript content
        functions = self.extract_js_functions(responseStr)
        for function in functions:
            self.functions_with_links.append((function, base_url))

        # Extract sinks and add them to the list
        sinks = self.extract_js_sinks(responseStr)
        for sink in sinks:
            self.js_sinks_with_links.append((sink, base_url))

    def fetch_and_extract_functions_and_sinks_from_links(self):
        for js_link in self.js_links:
            if not js_link.startswith('http'):
                # Create full URL if relative
                try:
                    base_url = self._callbacks.getSiteMap("") # Get the base URL from the site map
                    if base_url:
                        base_url = base_url[0].getUrl()  # example: just fetching the first URL for base context
                        full_url = self._helpers.buildUrl(base_url, js_link).toString() # Proper construction
                        js_link = full_url
                    else:
                        self._callbacks.printOutput("Error: Base URL could not be fetched.")
                        continue

                except Exception as e:
                    self._callbacks.printOutput("Error building URL from '{}': {}".format(js_link, str(e)))
                    continue

            try:
                if not self.is_valid_url(js_link):
                    self._callbacks.printOutput("Invalid URL: {}".format(js_link))
                    continue

                # Build HttpService correctly to avoid coercion issues
                url_obj = self._helpers.buildHttpRequest(js_link)
                if url_obj is None:
                    self._callbacks.printOutput("Failed to build request for: {}".format(js_link))
                    continue
                
                # Creating HTTP service
                service = self._helpers.buildHttpService(js_link.getHost(), js_link.getPort(), js_link.getProtocol())
                response_info = self._callbacks.makeHttpRequest(service, url_obj)

                # Extract functions and sinks from the response content
                if response_info.getResponse() is not None:
                    response_str = self._helpers.bytesToString(response_info.getResponse())
                    functions = self.extract_js_functions(response_str)
                    for function in functions:
                        self.functions_with_links.append((function, js_link))

                    sinks = self.extract_js_sinks(response_str)
                    for sink in sinks:
                        self.js_sinks_with_links.append((sink, js_link))

            except Exception as e:
                self._callbacks.printOutput("Error fetching JS link: {}".format(str(e)))

    def extract_new_links(self, responseStr):
        """ Extract new links from the response body """
        json_link_pattern = r'"(http[^"]+)"'
        new_links_found = re.findall(json_link_pattern, responseStr)

        for link in new_links_found:
            if link not in self.js_links:  # Avoid processing the same link multiple times
                self.js_links.append(link)
                self._callbacks.printOutput("Extracted new link from response: {}".format(link))

    def extract_js_functions(self, js_code):
        """ Extract JavaScript functions using regex """
        function_pattern = r'function\s+([a-zA-Z_$][0-9a-zA-Z_$]*)\s*\('
        matches = re.findall(function_pattern, js_code)
        return matches

    def extract_js_sinks(self, js_code):
        """ Extract known JavaScript sinks using regex """
        sink_patterns = [
            r'eval\s*\(',             # eval()
            r'document\.write\s*\(',  # document.write()
            r'innerHTML\s*=',         # assignment to innerHTML
            r'setTimeout\s*\(',       # setTimeout()
            r'setInterval\s*\(',      # setInterval()
            r'XMLHttpRequest\s*\(',    # XMLHttpRequest
            r'fetch\s*\(',            # fetch()
            # Add more sink patterns as needed…
        ]
        
        sinks_found = []
        for pattern in sink_patterns:
            matches = re.findall(pattern, js_code)
            sinks_found.extend([match for match in matches])  # Collect all matches
        # Clean duplicates
        sinks_found = list(set(sinks_found))
        return sinks_found

    def fetch_links_from_sitemap(self):
        """ Fetch links from the Burp Suite sitemap """
        sitemap = self._callbacks.getSiteMap("")
        for node in sitemap:
            url = node.getUrl()
            self._callbacks.printOutput("Sitemap URL: " + str(url))

            try:
                protocol = url.getProtocol()  # HTTP/HTTPS
                host = url.getHost()          # Host
                port = url.getPort()          # Port

                # Default ports if not specified
                if port == -1:
                    port = 80 if protocol == 'http' else 443

                # Create HTTP service with all necessary parameters
                http_service = self._helpers.buildHttpService(host, port, protocol)
                request = self._helpers.buildHttpRequest(url)
                response_info = self._callbacks.makeHttpRequest(http_service, request)

                if response_info.getResponse() is not None:
                    response_str = self._helpers.bytesToString(response_info.getResponse())
                    self.extract_js_and_sinks(response_str, str(url))
                    self.extract_new_links(response_str)

            except Exception as e:
                self._callbacks.printOutput("Error fetching sitemap URL: {}".format(str(e)))

    def is_valid_url(self, url):
        """ Check if the URL is valid """
        return url.startswith("http") or url.startswith("https")

class ClassWindowAdapter(WindowAdapter):
    def __init__(self, extender):
        self.extender = extender

    def windowClosing(self, event):
        # Instead of closing the application, hide the frame
        self.extender.frame.setVisible(False)
