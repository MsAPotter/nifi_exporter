package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/juju/errors"
	log "github.com/sirupsen/logrus"
)

const tokenExpirationMargin = time.Minute

type Credentials struct {
	CaCertificates string
}

type Client struct {
	baseURL     string
	client      http.Client
	credentials url.Values

	token                    string
	tokenMx                  sync.Mutex
	tokenExpirationTimestamp int64
}

type jwtPayload struct {
	Audience          string `json:"aud"`
	ExpirationTime    int64  `json:"exp"`
	IssuedAt          int64  `json:"iat"`
	Issuer            string `json:"iss"`
	Kid               int    `json:"kid"`
	PreferredUsername string `json:"preferred_username"`
	Subject           string `json:"sub"`
}

func NewClient(baseURL, caCertificates string) (*Client, error) {
	log.Info("Inside client.go, in NewClient FUNCTION")
	c := Client{
		baseURL: strings.TrimRight(baseURL, "/") + "/nifi-api",
		// credentials: caCertificates,
		// credentials: url.Values{
		// 	"caCertificates": {caCertificates},
		// },
		credentials: url.Values{
			"caCertificates": []string{caCertificates},
		},
	}

	// log.Printf("print new client c = %v\n", c)	/////////
	log.Printf("print new client c.credentials = %v\n", c.credentials)	/////////
	// log.Printf("print credentials = %v\n", url.Values)	/////////
	// log.Printf(url.Values)	/////////
	// log.Print(url.Values)	/////////

	// log.Info("Printing the caCertificates ==== "+ caCertificates)
	
	if caCertificates != "" {
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(caCertificates)); !ok {
			return nil, errors.New("Invalid CA certificates.")
		}
		for _, der := range certPool.Subjects() {
			var rdn pkix.RDNSequence
			if _, err := asn1.Unmarshal(der, &rdn); err != nil {
				return nil, errors.Trace(err)
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			log.WithFields(log.Fields{
				"commonName":   name.CommonName,
				"organization": name.Organization,
			}).Infof("Loaded CA certificate for %s: %s", baseURL, name.CommonName)
		}
		c.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		}
	}
	return &c, nil
}

func (c *Client) GetCounters(nodewise bool, clusterNodeId string) (*CountersDTO, error) {
	log.Info("Inside client.go, in GetCounters FUNCTION")
	query := url.Values{}
	if nodewise {
		query.Add("nodewise", "1")
	} else {
		query.Add("nodewise", "0")
	}
	if len(clusterNodeId) > 0 {
		query.Add("clusterNodeId", clusterNodeId)
	}

	var entity CountersEntity
	if err := c.request("/counters", query, &entity); err != nil {
		return nil, errors.Trace(err)
	}
	return &entity.Counters, nil
}

func (c *Client) GetProcessGroup(id string) (*ProcessGroupEntity, error) {
	log.Info("Inside client.go, in GetProcessGroup FUNCTION")
	var entity ProcessGroupEntity
	if err := c.request("/process-groups/"+id, nil, &entity); err != nil {
		return nil, errors.Trace(err)
	}
	return &entity, nil
}

func (c *Client) GetProcessGroups(parentID string) ([]ProcessGroupEntity, error) {
	log.Info("Inside client.go, in GetProcessGroups FUNCTION")
	var entity ProcessGroupsEntity
	if err := c.request("/process-groups/"+parentID+"/process-groups", nil, &entity); err != nil {
		return nil, errors.Trace(err)
	}
	return entity.ProcessGroups, nil
}

// GetConnections traverses the process group hierarchy returning information about
// all connections
func (c *Client) GetConnections(parentID string) ([]ConnectionEntity, error) {
	log.Info("Inside client.go, in GetConnections FUNCTION")
	var entity ConnectionsEntity
	if err := c.getDeepConnections(parentID, &entity); err != nil {
		return nil, err
	}
	return entity.Connections, nil

}

func (c *Client) getDeepConnections(parentID string, connectionsEntity *ConnectionsEntity) error {
	log.Info("Inside client.go, in getDeepConnections FUNCTION")
	var entity ConnectionsEntity

	// Get the connections for the current process group
	if err := c.request("/process-groups/"+parentID+"/connections", nil, &entity); err != nil {
		return errors.Trace(err)
	}

	// And the child process groups

	var pgentity ProcessGroupsEntity
	if err := c.request("/process-groups/"+parentID+"/process-groups", nil, &pgentity); err != nil {
		return errors.Trace(err)
	}

	for _, pg := range pgentity.ProcessGroups {
		if err := c.getDeepConnections(pg.ID, connectionsEntity); err != nil {
			return err
		}
	}
	connectionsEntity.Connections = append(connectionsEntity.Connections, entity.Connections...)
	return nil
}

// GetDeepProcessGroups traverses the process group hierarchy returning information about
// this and all child process groups
func (c *Client) GetDeepProcessGroups(parentID string) ([]ProcessGroupEntity, error) {
	log.Info("Inside client.go, in GetDeepProcessGroups FUNCTION")
	var entity ProcessGroupsEntity
	if err := c.getDeepProcessGroups(parentID, &entity); err != nil {
		return nil, err
	}
	return entity.ProcessGroups, nil

}

func (c *Client) getDeepProcessGroups(parentID string, groupsEntity *ProcessGroupsEntity) error {
	log.Info("Inside client.go, in getDeepProcessGroups FUNCTION")
	var entity ProcessGroupsEntity
	if err := c.request("/process-groups/"+parentID+"/process-groups", nil, &entity); err != nil {
		return errors.Trace(err)
	}

	for _, pg := range entity.ProcessGroups {
		if err := c.getDeepProcessGroups(pg.ID, groupsEntity); err != nil {
			return err
		}
	}
	groupsEntity.ProcessGroups = append(groupsEntity.ProcessGroups, entity.ProcessGroups...)
	return nil
}

func (c *Client) GetSystemDiagnostics(nodewise bool, clusterNodeId string) (*SystemDiagnosticsDTO, error) {
	log.Info("Inside client.go, in GetSystemDiagnostics FUNCTION")
	query := url.Values{}
	log.Info("Pringing url.Values......")
	// log.Info(url.Values{})	--> cannot use url.Values literal (type url.Values) as type string in argument to logrus.Printf
	// log.Printf(url.Values{})  --> cannot use url.Values literal (type url.Values) as type string in argument to logrus.Printf
	fmt.Printf("%+v\n", *query)

	if nodewise {
		query.Add("nodewise", "1")
	} else {
		query.Add("nodewise", "0")
	}
	if len(clusterNodeId) > 0 {
		query.Add("clusterNodeId", clusterNodeId)
	}

	var entity SystemDiagnosticsEntity
	if err := c.request("/system-diagnostics", query, &entity); err != nil {
		return nil, errors.Trace(err)
	}
	return &entity.SystemDiagnostics, nil
}

func (c *Client) request(path string, query url.Values, responseEntity interface{}) error {
	log.Info("Inside client.go, in request FUNCTION")
	
	token, err := c.getToken()
	if err != nil {
		return errors.Trace(err)
	}

	reqURL := c.baseURL + path

	log.WithField("url", reqURL).Info("Requesting api resource......")
	if query != nil && len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return errors.Annotate(err, "Error while preparing API request")
	}
	req.Header.Add("Authorization", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return errors.Annotate(err, "NiFi API request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(responseEntity); err != nil {
			return errors.Annotate(err, "Invalid JSON response from NiFi")
		}
		return nil
	}

	messageBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Annotate(err, "Couldn't read error message from API response")
	}
	message := fmt.Sprintf(
		"API call returned an error: %s: %s",
		resp.Status,
		string(messageBytes),
	)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return errors.Unauthorizedf(message)
	} else {
		return errors.New(message)
	}

}



// func wrapHandlerWithLogging(wrappedHandler http.Handler) http.Handler {
//     return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
//         log.Printf("--> %s %s", req.Method, req.URL.Path)

//         lrw := NewLoggingResponseWriter(w)
//         wrappedHandler.ServeHTTP(lrw, req)

//         statusCode := lrw.statusCode
//         log.Printf("<-- %d %s", statusCode, http.StatusText(statusCode))
//     })
// }

func (c *Client) getToken() (string, error) {
	log.Info("Inside client.go, in getToken FUNCTION")
	if atomic.LoadInt64(&c.tokenExpirationTimestamp) < time.Now().Add(tokenExpirationMargin).Unix() {
		c.authenticate()
		log.Printf("print new client c.tokenExpirationTimestamp = %v\n", c.tokenExpirationTimestamp)	/////////
	}
	return c.token, nil
}

func (c *Client) authenticate() error {
	log.Info("Inside client.go, in authenticate FUNCTION")
	// c.tokenMx.Lock()
	// defer c.tokenMx.Unlock()
	if c.tokenExpirationTimestamp > time.Now().Add(tokenExpirationMargin).Unix() {
		log.Info("Inside if stmt tokenExpirationTimestamp")
		return nil
	}
	log.Info("Printing c.tokenExpirationTimestamp..... ")
	log.Print(c.tokenExpirationTimestamp)
	log.Info("Printing time.Now().Add(tokenExpirationMargin).Unix().... ")
	log.Print(time.Now().Add(tokenExpirationMargin).Unix())
	
	log.Info("Printing resp.StatusCode ..... ")
	log.Print(resp.StatusCode)

	log.WithFields(log.Fields{
		"url":      c.baseURL,
		"caCertificates": c.credentials,
	}).Info("Authentication token has expired, reauthenticating...")

	if urlError,ok :=  err.(*url.Error)  ; ok {
		if urlError.Error() == "net/http: TLS handshake timeout" {
			log.Info("Handshake failed.....")
		}
	}

	resp, err := c.client.PostForm(c.baseURL+"/access/token", c.credentials)

	log.Info("Printing resp.StatusCode ..... ")
	log.Print(resp.StatusCode)

	if err != nil {
		return errors.Annotate(err, "Couldn't request access token from NiFi")
	}
	defer resp.Body.Close()



	// log.Info("Printing resp.....")	/////
	// log.Info(resp)	//////
	// log.Info("Printing respBody.....")	/////
	// log.Info(resp.Body)	//////


	// log.Info("Printing resp with url and certs.....")	/////
	// log.WithFields(log.Fields{	///////
	// 	"url":      c.baseURL,
	// 	"caCertificates": c.credentials.Get("caCertificates"),
	// }).Info(resp)

	// log.Info("Printing respBody with url and certs.....")	/////
	// log.WithFields(log.Fields{	///////
	// 	"url":      c.baseURL,
	// 	"caCertificates": c.credentials.Get("caCertificates"),
	// }).Info(resp.Body)


	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Annotate(err, "Couldn't read access token response from NiFi")
	}
	body := strings.TrimSpace(string(bodyBytes))

	// log.Info("Printing body.....")	/////
	// log.Info(body)	//////


	// log.Info("Printing body with url and certs.....")	/////
	// log.WithFields(log.Fields{	///////
	// 	"url":      c.baseURL,
	// 	"caCertificates": c.credentials.Get("caCertificates"),
	// }).Info(body)

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		log.Info("inside resp.StatusCode == http.StatusOK function....")	//////

		jwtParts := strings.SplitN(body, ".", 3)

		if len(jwtParts) < 2 {
			return errors.Annotate(err, "Invalid access token response from NiFi: Missing JWT payload")
		}
		jwtPayloadJson, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
		if err != nil {
			return errors.Annotate(err, "Invalid access token response from NiFi: Payload is not valid Base64")
		}
		var payload jwtPayload
		if err := json.Unmarshal(jwtPayloadJson, &payload); err != nil {
			return errors.Annotate(err, "Invalid access token response from NiFi: Payload is not valid JSON")
		}

		c.token = "Bearer " + body
		atomic.StoreInt64(&c.tokenExpirationTimestamp, payload.ExpirationTime)

		log.WithFields(log.Fields{
			"url":             c.baseURL,
			"caCertificates":        c.credentials.Get("caCertificates"),
			"tokenExpiration": time.Unix(c.tokenExpirationTimestamp, 0).String(),
		}).Info("Authentication successful.")
		return nil
	} else if resp.StatusCode == http.StatusUnauthorized {
		return errors.Unauthorizedf(body)
	} else {
		return errors.New(body)
	}
}

/////////// NEW
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	log.Info("Inside NewLoggingResponseWriter function")
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	log.Info("Inside loggingResponseWriter function")
	lrw.statusCode = code
	log.Print(code)
	lrw.ResponseWriter.WriteHeader(code)
}

func wrapHandlerWithLogging(wrappedHandler http.Handler) http.Handler {
	log.Info("Inside wrapHandlerWithLogging function")
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log.Info("Inside http.HandlerFunc function")
		log.Printf("--> %s %s", req.Method, req.URL.Path)

		lrw := NewLoggingResponseWriter(w)
		wrappedHandler.ServeHTTP(lrw, req)

		statusCode := lrw.statusCode
		log.Printf("<-- %d %s", statusCode, http.StatusText(statusCode))
	})
}