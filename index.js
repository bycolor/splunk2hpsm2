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
            this.mod_cors = require('cors');
            this.cors = this.mod_cors();
        } catch(err) {
            console.debug('\n Module cors can not be loaded, aborting...\n', err.message);
            return false;
        };

        try {
            this.mod_express = require('express');
            this.express = this.mod_express();
        } catch(err) {
            console.debug('\n Module express can not be loaded, aborting...\n', err.message);
            return false;
        };

        // Initialize data
        this.data = [];
        // Don't forget to reset the session key!
        this.data.splunk = [];
            this.data.splunk.xmlSessionkey = false;
            this.data.splunk.sessionkey = false;
        this.data.hpsm = [];

        // Set up some handy URLs
        this.url = [];
        this.url.splunk = [];
            this.url.splunk['root'] = 'https://splunk.unicreditgroup.eu/en-US/splunkd/__raw/services/';
            this.url.splunk['login'] = this.url.splunk['root'] + 'auth/login';
            this.url.splunk['messages'] = this.url.splunk['root'] + 'messages';
            this.url.splunk['searches'] = this.url.splunk['root'] + 'saved/searches';
            this.url.splunk['users'] = this.url.splunk['root'] + 'authentication/users';
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
                //console.debug('parseXML - result.response: ', result.response);

                // For sessionkey only
                if (result && result.response && result.response.sessionKey) {
                    _this.data.splunk.sessionkey = result.response.sessionKey[0]
                };
                return result;
            } else {
                // Error parsing XML
                console.debug('parseXML - XML parsing failed, cant extract sessionkey: ', err);
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

        console.log('\n getData() calling URL: ' + options.url);
        
        // Execute the call and store it as a promise
        return this.mod_reqPromise(options);
    };


    Splunk.prototype.getSplunkSessionkey = function() {
        var _this = this;

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

        console.debug('\n getSplunkSessionkey - options: \n', options);

        // Get raw login response
        return this.getData(options).then(function (response) {
            if (!response) { 
                console.debug('getSplunkSessionkey - No response');
                return false 
            };

            _this.data.splunk.xmlSessionkey = response.body;

            // Extract session key from raw login response
            if (_this.data.splunk.xmlSessionkey) {
                _this.parseXML(_this.data.splunk.xmlSessionkey);
            };

            if (_this.data.splunk.sessionkey) {
                return _this.getSplunkSavedSearches();
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
            method: 'GET',
            url: _this.url.splunk['users'],
            port: 443,
            insecure: false,
            rejectUnauthorized: false,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authentication': 'Splunk ' + _this.data.splunk.sessionkey,
                'Cookie': "s_vi=[CS]v1|2D0DFA8E85314BF0-6000011460003F5C[CE]; s_pers=%20s_adserv%3Dunicreditgroup-eu-it%7C1520876172518%3B%20gvsC%3DNew%7C1520876174789%3B%20channel_stack%3D%255B%255B%27Natural%252520Search%27%252C%271520874405271%27%255D%255D%7C1678640805271%3B%20s_fid%3D13ADAF2FF0A53024-39470E951B934601%7C1584032901476%3B%20s_visit%3D1%7C1520876301480%3B%20gpv_pageName%3Ducg%253Amicrosites%253Aubis%7C1520876301484%3B%20s_nr%3D1520874501488-Repeat%7C1552410501488%3B%20s_pv10%3Ducg%253Amicrosites%253Aubis%7C1520876301497%3B; s_sess=%20s_cc%3Dtrue%3B%20s_sq%3D%3B%20s_ppv%3D100%3B%20channel%3DNatural%2520Search_https%253A%252F%252Fwww.google.at%252F_Google%2520-%2520Austria_No%2520Keyword%3B%20s_evar7%3DD%253Dc7%3B; splunkweb_csrf_token_8000=3826282082636209158; session_id_8000=2015267127c777716fa765e9f5bc7bb46103b5ce; splunkd_8000=4qVXezTxv2wCQIHF8EC8cACv4LKl1YdbOGaORS8M97x3s8r75kCUWGoVno3_PQcFtm6p6rqJIQcgUndwzE8U5UM9L8geF0IQ23WmMCAUG_o5gWMoO_LMRJmoapir6dCbUaauH8slZQd2tC",
                'Set-Cookie': "splunkd_8000=4qVXezTxv2wCQIHF8EC8cACv4LKl1YdbOGaORS8M97x3s8r75kCUWGoVno3_PQcFtm6p6rqJIQcgUndwzE8U5UM9L8geF0IQ23WmMCAUG_o5gWMoO_LMRJmoapir6dCbUaauH8slZQd2tC; Path=/; HttpOnly; Max-Age=3600; Expires=Mon, 07 May 2018 16:33:46 GMT",
                'Set-Cookie': "splunkweb_csrf_token_8000=3826282082636209158; Path=/; Max-Age=157680000; Expires=Sat, 06 May 2023 15:33:46 GMT"
            },
            //form: 'username=' + this.credentials.splunk.user + '&password=' + encodeURIComponent(this.credentials.splunk.pass)
        };

        console.debug('\n getSplunkSavedSearches - options: \n', options);

        // Get raw response
        return this.getData(options).then(function (response) {
            if (!response) { 
                console.debug('getSplunkSavedSearches - No response');
                return false 
            };

            _this.data.splunk.response = _this.parseXML(response.body);
            
            console.debug('getSplunkSavedSearches - _this.data.splunk.response:  \n', _this.data.splunk.response);

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


    /*
    Splunk.prototype.loginSplunk = function() {
        var _this = this;

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


        console.debug('loginSplunk - options: ', options);

        // Set the sessionkey
        return this.getSplunkSessionkey(options);
    };
       */


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
        return this.getData(options);
    };


    Splunk.prototype.startServer = function() {
        var _this = this;
        
       this.express.use(this.cors);
       this.express.options("*", this.cors);

        var server = this.express.get('/api/splunk/sessionkey', function(request, response) {
            if (!request) { 
                response.send({error: true, message: 'No request object'});
                return false;
            };

            if (!request.query) { 
                response.send({error: true, message: 'No request request query'});
                return false;
            };

            if (request.query.user && request.query.pass) {
                _this.credentials.splunk.user = request.query.user;
                _this.credentials.splunk.pass = request.query.pass;
                
                console.log('--0--');

                _this.getSplunkSessionkey().then(function(res) {
                    // Shouldt this be async with the login call?
                    console.log('--1--');
                    if (_this.data.splunk.sessionkey) {
                        console.log('--2--');
                        response.send({error: false, sessionkey: _this.data.splunk.sessionkey});
                    } else {
                        console.log('--3--');
                        response.send({error: true, message: "No sessionkey retrieved"});
                    };
                }, function(fail) {
                    console.log('--4--');
                });
            } else {
                console.log('--5--');
                response.send({error: true, message: 'No request params'});
            }
        });

        server.listen(8000);
    };


    Splunk.prototype.stopServer = function(server) {
        // Sometime later... shutdown the server.
        server.shutdown(function() {
            console.log('Everything is cleanly shutdown.');
        });
    };


    Splunk.prototype.powerUp = function() {

        // Set up initial data 
        if (!this.init()) { return false };

        this.startServer();
    };
};

// ----------------------------------------------------------------------------------------------
// Power up!
var oSplunk = new Splunk();
var splunkData = oSplunk.powerUp();
