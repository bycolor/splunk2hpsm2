var Splunk = function() {
    Splunk.prototype.init = function(credentials) {
        // Import necessary extra modules
        try {
            this.mod_reqPromise = require('request-promise');
        } catch(err) {
            console.debug('Module request-promise can not be loaded, aborting...\n', err);
            return false;
        };

        try {
            this.mod_xml2js = require('xml2js');
            this.xmlParser = new this.mod_xml2js.Parser();
        } catch(err) {
            console.debug('Module xml2js can not be loaded, aborting...\n', err);
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
            this.url.splunk['searches'] = this.url.splunk['root'] + 'saved/searches';
            this.url.splunk['fired-alerts'] = this.url.splunk['root'] + 'alerts/fired_alerts';
        this.url.hpsm = [];
            this.url.hpsm['root'] = 'https://servicemanager.intranet.unicreditgroup.eu/sm/9/rest/incidents';
        
        // Set up credentials
        this.credentials = [];
        this.credentials.splunk = [];
            this.credentials.splunk['user'] = (credentials && credentials.splunk['user']) || 'C310865_14';
            this.credentials.splunk['pass'] = (credentials && credentials.splunk['pass']) || '@*HC5k@+';
        this.credentials.hpsm = [];

        return true;
    };

    
    Splunk.prototype.parseXML = function(data) {
        if (!data) { return false };

        // Extract the session key
        this.xmlParser.parseString(data, function (err, result) {
            if (!err) {
                // Success parsing XML
                console.debug('parseXML - result.response.sessionKey: ', result.response.sessionKey[0]);
            } else {
                // Error parsing XML
                console.debug('parseXML - parseXML - XML parsing failed, cant extract sessionkey: ', err);
            };
        });
    };

    
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

        console.log('calling ' + options.url);
        
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
                _this.data.splunk['sessionkey'] = _this.parseXML(_this.data.splunk['xml-sessionkey']);
            };

            return response;
        })
        .catch(function (err) {
            console.debug('getSplunkSessionkey - Call failed: ', err);
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
            console.debug('processHPSMData - Call failed: ', err);
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


    Splunk.prototype.powerUp = function() {
        if (this.loginSplunk()) {
            // Splunk Login success
        } else {
            // Splunk Login failed
        };

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
