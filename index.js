var Splunk = function() {
    Splunk.prototype.init = function(credentials) {
        // Import necessary extra modules
        try {
            this.mod_reqPromise = require('request-promise');
        } catch(err) {
            console.debug('\n Module request-promise can not be loaded, aborting...', err.message);
            return false;
        };

        try {
            this.mod_xml2js = require('xml2js');
            this.xmlParser = new this.mod_xml2js.Parser();
        } catch(err) {
            console.debug('\n Module xml2js can not be loaded, aborting...\n', err.message);
            return false;
        };

        try {
            this.mod_http = require('http');
        } catch(err) {
            console.debug('\n Module http can not be loaded, aborting...\n', err.message);
            return false;
        };

        try {
            this.mod_express = require('express');
            this.express = this.mod_express();
            console.log('------- loaded express ---------')
        } catch(err) {
            console.debug('\n Module express can not be loaded, aborting...\n', err.message);
            return false;
        };

        // Initialize data
        this.data = [];
        // Don't forget to reset the session key!
        this.data.splunk = [];
            this.data.splunk['xml-sessionkey'] = false;
            this.data.splunk['sessionkey'] = false;
        this.data.hpsm = [];

        // Set up some handy URLs
        this.url = [];
        this.url.splunk = [];
            this.url.splunk['root'] = 'https://splunk.unicreditgroup.eu/en-US/splunkd/__raw/services/';
            this.url.splunk['login'] = this.url.splunk['root'] + 'auth/login';
            this.url.splunk['messages'] = this.url.splunk['root'] + 'messages';
            this.url.splunk['searches'] = this.url.splunk['root'] + 'saved/searches';
            this.url.splunk['fired-alerts'] = this.url.splunk['root'] + 'alerts/fired_alerts';
        this.url.hpsm = [];
            this.url.hpsm['root'] = 'https://servicemanager.intranet.unicreditgroup.eu/sm/9/rest/incidents';
        
        // Set up credentials
        this.credentials = [];
        this.credentials.splunk = [];
            // IMPORTANT!
            // Do NOT push on GitHub until current credentials have expired!
            this.credentials.splunk['user'] = credentials && credentials.splunk['user'] ? credentials.splunk['user'] : '';
            this.credentials.splunk['pass'] = credentials && credentials.splunk['pass'] ? credentials.splunk['pass'] : '';
        this.credentials.hpsm = [];

        return true;
    };

    
    Splunk.prototype.parseXML = function(data) {
        var _this = this;
        if (!data) { return false };

        // Extract the session key
        return this.xmlParser.parseString(data, function (err, result) {
            if (!err) {
                // Success parsing XML
                console.debug('parseXML - result.response.sessionKey[0]: ', result.response.sessionKey[0]);
                _this.data.splunk['sessionkey'] = result.response.sessionKey[0];
                return result.response.sessionKey[0];
            } else {
                // Error parsing XML
                console.debug('parseXML - parseXML - XML parsing failed, cant extract sessionkey: ', err);
                _this.data.splunk['sessionkey'] = false;
                return false;
            };
        });
    };

    
    // General getter
    Splunk.prototype.getData = function(options) {
        var _this = this;

        if (!options || !options.url) { return false };

        // Prepare default + new call params
        var options = {
            method: options.method || 'POST',
            resolveWithFullResponse: options.resolveWithFullResponse ||true,
            url: options.url,
            json: options.json || true,
            port: options.port || 8080,
            // jar: cookiejar // Tells rp to include cookies in jar that match uri
            headers: options.headers || '',
            rejectUnauthorized: typeof options.rejectUnauthorized !== 'undefined' ? options.rejectUnauthorized : true,
            form: options.form || ''
        };

        console.log('\n calling ' + options.url);
        
        // Execute the call and store it as a promise
        var reqPromise = this.mod_reqPromise(options);

        return reqPromise;
    };


    Splunk.prototype.getSplunkSessionkey = function(reqPromise) {
        var _this = this;

        reqPromise.then(function (response) {
            if (!response) { 
                console.debug('getSplunkSessionkey - No response');
                return false 
            };

            _this.data.splunk['xml-sessionkey'] = response.body;

            // Extract session key from raw login response
            if (_this.data.splunk['xml-sessionkey']) {
                _this.parseXML(_this.data.splunk['xml-sessionkey']);
            };

            if (_this.data.splunk['sessionkey']) {
                console.debug('getSplunkSessionkey - _this.data.splunk[sessionkey]: ', _this.data.splunk['sessionkey']);
                _this.getSplunkSavedSearches();
            } else {
                console.debug('getSplunkSessionkey - No sessionkey');
            };

            return response;
        })
        .catch(function (err) {
            console.debug('\n getSplunkSessionkey - Call failed: \n', err.message);
            return err;
        });
    };

    Splunk.prototype.getSplunkSavedSearches = function() {
        var _this = this;

        // Prepare call params
        var options = {
            method: 'POST',
            url: _this.url.splunk['messages'],
            port: 443,
            insecure: false,
            rejectUnauthorized: false,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authentication': 'Splunk ' + _this.data.splunk['sessionkey']
            },
            form: 'username=' + this.credentials.splunk.user + '&password=' + encodeURIComponent(this.credentials.splunk.pass)
        };


        console.debug('\n getSplunkSavedSearches - options: \n', options);

        // Get raw response
        var promise_getData = this.getData(options);
        promise_getData.then(function (response) {
            if (!response) { 
                //console.debug('getSplunkSavedSearches - No response');
                return false 
            };

            _this.data.splunk['response'] = response;
            //console.debug('getSplunkSavedSearches - _this.data.splunk[response]:  \n', _this.data.splunk['response']);

            return response;
        })
        .catch(function (err) {
            console.debug('\n getSplunkSavedSearches - Call failed: \n', err.message);
            return err;
        });
    };


    Splunk.prototype.processHPSMData = function(reqPromise) {
        var _this = this;

        reqPromise.then(function (response) {
            if (!response) { return false }

            console.debug('response: ', response.body);

            return response;
        })
        .catch(function (err) {
            console.debug('\n processHPSMData - Call failed: \n', err.message);
            return err;
        });
    };


    Splunk.prototype.loginSplunk = function() {
        var _this = this;

        // Set up initial data 
        if (!this.init()) { return false };

        // Prepare call params
        var options = {
            method: 'POST',
            url: _this.url.splunk['login'],
            port: 443,
            insecure: false,
            rejectUnauthorized: false,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            form: 'username=' + this.credentials.splunk.user + '&password=' + encodeURIComponent(this.credentials.splunk.pass)
        };

        // Get raw login response
        var promise_getData = this.getData(options);
        // Set the sessionkey
        this.getSplunkSessionkey(promise_getData);

        return this.data.splunk['sessionkey'] || false;
    };


    Splunk.prototype.loginHPSM = function() {
        var options = {
            method: 'GET',
            url: _this.url.hpsm['incidents'],
            port: 443,
            // jar: cookiejar // Tells rp to include cookies in jar that match uri
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            form: ''
        };

        console.debug('loginHPSM - options: ', options);

        // Get raw HPSM login response
        var promise_getData = this.getData(options);

        return this.data.hpsm['response'] || false;
    };


    Splunk.prototype.startServer = function() {
        var _this = this;
        // Handle your routes here, put static pages in ./public and they will server

        // Create HTTP server and listen on port 8000 for requests
        /*
        var server = this.mod_http.createServer(function(request, response) {
            console.debug('startServer - request: ', request);

            response.writeHead(200, {'Content-Type': 'text/plain'});
            response.end('{id: "1"}');
        });
        */

        var server = this.express.get('/api/splunk/sessionkey', function(request, response) {
            //console.debug('startServer - request: ', request);
            if (request) {
                //console.debug(request);
                if (request.user && request.pass) {
                    _this.credentials.splunk['user'] = request.user;
                    _this.credentials.splunk['pass'] = request.pass;
                    _this.loginSplunk();
                    // Shouldt this be async with the login call?
                    response.send({sessionkey: _this.data.splunk['sessionkey']});
                } else {
                    response.send({message: 'no data'});
                }
            };
        });

        //server = require('http-shutdown')(server);
        server.listen(8000);
    };


    Splunk.prototype.stopServer = function(server) {
        // Sometime later... shutdown the server.
        server.shutdown(function() {
            console.log('Everything is cleanly shutdown.');
        });
    };


    Splunk.prototype.powerUp = function() {
        if (this.loginSplunk()) {
            // Splunk Login success
        } else {
            // Splunk Login failed
        };

        this.startServer();

        /*
        if (this.loginHPSM()) {
            // HPSM Login success
        } else {
            // HPSM Login failed
        };
        */
    };
};

// ----------------------------------------------------------------------------------------------
// Power up!
var oSplunk = new Splunk();
var splunkData = oSplunk.powerUp();
