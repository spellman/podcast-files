import Cocoa
import CommonCrypto

struct BackblazeInfo {
    let backblazeApiKeyId: String
    let backblazeApiKey: String
    let backblazeBucketName: String
    let authorName: String
}

struct FinishRequestDebugStruct: Decodable {
    let fileId: String
    let partSha1Array: [String]
}

struct BackblazeErrorResponse: Decodable {
    let status: Int
    let code: String
    let message: String
}

struct BackblazeAuthInfo: Decodable {
    struct BackblazeAPIInfo: Decodable {
        struct BackblazeStorageAPI: Decodable {
            let apiUrl: URL
            let absoluteMinimumPartSize: Int
            let recommendedPartSize: Int
        }
        
        let storageApi: BackblazeStorageAPI
    }
    
    let accountId: String
    let apiInfo: BackblazeAPIInfo
    let authorizationToken: String
}

struct Bucket: Decodable {
    let bucketId: String
}

struct ListBucketsResponse: Decodable {
    let buckets: [Bucket]
}

struct UploadNonLargeFileUrlResponse: Decodable {
    let authorizationToken: String
    let uploadUrl: URL
}

struct UploadNonLargeFileResponse: Decodable {
    let fileName: String
}

struct StartLargeFileUploadResponse: Decodable {
    let fileId: String
}

struct UploadLargeFilePartUrlResponse: Decodable {
    let authorizationToken: String
    let fileId: String
    let uploadUrl: URL
}

struct UploadPart {
    let partNumber: Int
    let partStart: UInt64
    let partSize: Int
}

/**
 * Calculate the part size. We try to upload as large of parts as possible, up to the recommended part size.
 *
 * The Backblaze docs say:
 * * The minimum part size is 5,000,000 bytes.
 * * The recommended part size is 100,000,000 bytes.
 *
 * When I try to upload a single part of size 8.3MB as a large file upload, however, the response says large files must have at least 2 parts.
 */
func partSize(fileSize: Int, minimumPartSize: Int, recommendedPartSize: Int) -> Int? {
    if fileSize <= minimumPartSize {
        return nil
    }
    else if fileSize < recommendedPartSize / 2 {
        return minimumPartSize
    }
    else if fileSize < recommendedPartSize {
        return max(minimumPartSize, recommendedPartSize / 2)
    }
    else {
        return recommendedPartSize
    }
}

func uploadParts(fileSize: Int, regularPartSize: Int) -> [UploadPart] {
    return Array(sequence(first: UploadPart(partNumber: 1, partStart: 0, partSize: min(fileSize, regularPartSize)), next: {
        let startByte = ($0.partStart + UInt64($0.partSize))
        
        guard startByte < fileSize else {
            return nil
        }
        let partSize = Int(startByte) + regularPartSize < fileSize
        ? Int(startByte) + regularPartSize
        : fileSize - Int(startByte)
        
        return UploadPart(partNumber: $0.partNumber + 1, partStart: startByte, partSize: partSize)
    }))
}

struct UploadedPart {
    let partNumber: Int
    let partSha1: String
}

struct FinishLargeFileUploadResponse: Decodable {
    let action: String
}

func backblazeFileURL(bucketName: String, fileName: String) -> URL {
    return URL(string: "https://f002.backblazeb2.com/file/\(bucketName.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)!)/\(fileName.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)!)")!
}

func appendToFileNameKeepingExtension(append appendage: String, to filePath: URL) -> String {
    filePath.deletingPathExtension().lastPathComponent + appendage + (filePath.pathExtension.count > 0 ? "." + filePath.pathExtension : "")
}

func tempFilePath() -> URL {
    return URL(fileURLWithPath: NSTemporaryDirectory(),
               isDirectory: true).appendingPathComponent(NSUUID().uuidString)
}

func makeZipArchive(inputPath: URL, outputPath: URL) -> NSError? {
    var error: NSError?
    
    let coordinator = NSFileCoordinator()
    coordinator.coordinate(readingItemAt: inputPath, options: [.forUploading], error: &error) { (zipUrl) in
        try! FileManager.default.moveItem(at: zipUrl, to: outputPath)
    }
    
    return error
}

/**
 * Source: https://stackoverflow.com/a/62465044/11903744
 */
func dataToHexEncodedString(data: Data) -> String {
    return data.reduce(into:"") { result, byte in
        result.append(String(byte >> 4, radix: 16))
        result.append(String(byte & 0x0f, radix: 16))
    }
}

/**
 * Sources:
 * https://stackoverflow.com/a/49878022/11903744
 * https://stackoverflow.com/a/58279290/11903744
 */
func sha1(url: URL) -> String? {
    do {
        let bufferSize = 1024 * 1024
        // Open file for reading:
        let file = try FileHandle(forReadingFrom: url)
        defer {
            file.closeFile()
        }
        
        // Create and initialize SHA1 context:
        var context = CC_SHA1_CTX()
        CC_SHA1_Init(&context)
        
        // Read up to `bufferSize` bytes, until EOF is reached, and update SHA1 context:
        while autoreleasepool(invoking: {
            // Read up to `bufferSize` bytes
            let data = file.readData(ofLength: bufferSize)
            if data.count > 0 {
                _ = data.withUnsafeBytes { bytesFromBuffer -> Int32 in
                  guard let rawBytes = bytesFromBuffer.bindMemory(to: UInt8.self).baseAddress else {
                    return Int32(kCCMemoryFailure)
                  }

                  return CC_SHA1_Update(&context, rawBytes, numericCast(data.count))
                }
                // Continue
                return true
            } else {
                // End of file
                return false
            }
        }) { }
        
        // Compute the SHA1 digest:
        var digestData = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = digestData.withUnsafeMutableBytes { bytesFromDigest -> Int32 in
          guard let rawBytes = bytesFromDigest.bindMemory(to: UInt8.self).baseAddress else {
            return Int32(kCCMemoryFailure)
          }

          return CC_SHA1_Final(rawBytes, &context)
        }
        
        return dataToHexEncodedString(data: digestData)
    } catch {
        print(error)
        return nil
    }
}

/**
 * Adapted from:
 * https://stackoverflow.com/a/49878022/11903744
 * https://stackoverflow.com/a/58279290/11903744
 */
func sha1(data: Data) -> String? {
    guard data.count > 0 else { return nil }
    
    // Create and initialize SHA1 context:
    var context = CC_SHA1_CTX()
    CC_SHA1_Init(&context)
    
    _ = data.withUnsafeBytes { bytesFromBuffer -> Int32 in
        guard let rawBytes = bytesFromBuffer.bindMemory(to: UInt8.self).baseAddress else {
            return Int32(kCCMemoryFailure)
        }
        
        return CC_SHA1_Update(&context, rawBytes, numericCast(data.count))
    }
    
    // Compute the SHA1 digest:
    var digestData = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
    _ = digestData.withUnsafeMutableBytes { bytesFromDigest -> Int32 in
        guard let rawBytes = bytesFromDigest.bindMemory(to: UInt8.self).baseAddress else {
            return Int32(kCCMemoryFailure)
        }
        
        return CC_SHA1_Final(rawBytes, &context)
    }
    
    return dataToHexEncodedString(data: digestData)
}

func fileSizeInBytes(filePath: String) throws -> Int {
    let fileAttributes = try FileManager.default.attributesOfItem(atPath: filePath)
    return (fileAttributes[.size] as? Int)!
}

class FileUploadDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    /**
     * Periodically informs the delegate of the progress of sending body content to the server.
     * Source: https://developer.apple.com/documentation/foundation/urlsessiontaskdelegate#2952843
     */
    func urlSession(_: URLSession, task: URLSessionTask, didSendBodyData: Int64, totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
        print("Sent \(totalBytesSent) of \(totalBytesExpectedToSend) = \(totalBytesSent / totalBytesExpectedToSend * 100)%")
    }
    
    /**
     * Tells the delegate that the task finished transferring data.
     * Source: https://developer.apple.com/documentation/foundation/urlsessiontaskdelegate#2952845
     */
    func urlSession(_: URLSession, task: URLSessionTask, didCompleteWithError: (any Error)?) {
        print("didCompleteWithError: \(String(describing: didCompleteWithError))")
    }
}

func getUserDefaultStringOrShowPreferencesWindow(userDefaultsKey: String, segueFrom: NSSeguePerforming) -> String? {
    let val = UserDefaults.standard.string(forKey: userDefaultsKey)
    
    guard val != nil && !val!.isEmpty else {
        segueFrom.performSegue!(withIdentifier: "showPreferences", sender: nil)
        return nil
    }
    
    return val
}

class ViewController: NSViewController {
    @IBOutlet weak var originalRecordingFilePath: NSTextField!
    @IBOutlet weak var originalRecordingLocalBackupFeedback: NSTextField!
    @IBOutlet weak var originalRecordingCloudBackupFeedback: NSTextField!
    
    @IBOutlet weak var finalEditFilePath: NSTextField!
    @IBOutlet weak var finalEditCloudBackupFeedback: NSTextField!
    
    @IBOutlet weak var audioTrackFilePath: NSTextField!
    @IBOutlet weak var audioTrackCloudBackupFeedback: NSTextField!
    
    @IBOutlet weak var anyFileFilePath: NSTextField!
    @IBOutlet weak var anyFileCloudBackupFeedback: NSTextField!
    
    func getBackblazeInfo() -> BackblazeInfo? {
        let backblazeApplicationKeyID = UserDefaults.standard.string(forKey: "backblazeApplicationKeyID")
        let backblazeApplicationKey = UserDefaults.standard.string(forKey: "backblazeApplicationKey")
        let backblazeBucketName = UserDefaults.standard.string(forKey: "backblazeBucketName")
        let authorName = UserDefaults.standard.string(forKey: "authorName")
        
        if backblazeApplicationKeyID == nil || backblazeApplicationKeyID!.isEmpty
            || backblazeApplicationKey == nil || backblazeApplicationKey!.isEmpty
            || backblazeBucketName == nil || backblazeBucketName!.isEmpty
            || authorName == nil || authorName!.isEmpty {
            performSegue(withIdentifier: "showPreferences", sender: nil)
            return nil
        }
        else {
            return BackblazeInfo(
                backblazeApiKeyId: backblazeApplicationKeyID!,
                backblazeApiKey: backblazeApplicationKey!,
                backblazeBucketName: backblazeBucketName!,
                authorName: authorName!
            )
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // TODO: LEFT OFF HERE. Use these in the code instead of the hard-coded values.
        // * Check if the values are set on application start. If not, display the preferences window to set them.
        // * If a value is not available when needed, fail with a message to set the value in preferences. (Enhancement, display preferences window and a flash message.)
        print("UserDefault backblazeApplicationKeyID: \(String(describing: UserDefaults.standard.string(forKey: "backblazeApplicationKeyID")))")
        print("UserDefault backblazeApplicationKey: \(String(describing: UserDefaults.standard.string(forKey: "backblazeApplicationKey")))")
        print("UserDefault backblazeBucketName: \(String(describing: UserDefaults.standard.string(forKey: "backblazeBucketName")))")

        getBackblazeInfo()
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }
    
    func browseFiles(allowedFileTypes: [String]? = nil) -> URL? {
        let dialog = NSOpenPanel()
        
        dialog.title = "Select file"
        dialog.showsHiddenFiles = true
        dialog.canChooseDirectories = false
        dialog.canChooseFiles = true
        dialog.allowsMultipleSelection = false
        dialog.showsResizeIndicator = true
        
        if allowedFileTypes != nil {
            dialog.allowedFileTypes = allowedFileTypes
        }
        
        dialog.runModal()
        
        return dialog.url
    }
    
    @IBAction func handleOriginalRecordingSelectFileButtonClicked(sender: NSButton) {
        let previouslySelectedPath = originalRecordingFilePath.stringValue
        
        originalRecordingFilePath.stringValue = ""
        originalRecordingLocalBackupFeedback.stringValue = ""
        originalRecordingCloudBackupFeedback.stringValue = ""
        
        if let fileURL = browseFiles() {
            originalRecordingFilePath.stringValue = fileURL.path
        }
        else {
            originalRecordingFilePath.stringValue = previouslySelectedPath
        }
    }
    
    @IBAction func handleFinalEditSelectFileButtonClicked(sender: NSButton) {
        let previouslySelectedPath = finalEditFilePath.stringValue
        
        finalEditFilePath.stringValue = ""
        finalEditCloudBackupFeedback.stringValue = ""
        
        if let fileURL = browseFiles() {
            finalEditFilePath.stringValue = fileURL.path
        }
        else {
            finalEditFilePath.stringValue = previouslySelectedPath
        }
    }
    
    @IBAction func handleAudioTrackSelectFileButtonClicked(sender: NSButton) {
        let previouslySelectedPath = finalEditFilePath.stringValue
        
        audioTrackFilePath.stringValue = ""
        audioTrackCloudBackupFeedback.stringValue = ""
        
        if let fileURL = browseFiles(allowedFileTypes: ["mp3"]) {
            audioTrackFilePath.stringValue = fileURL.path
        }
        else {
            audioTrackFilePath.stringValue = previouslySelectedPath
        }
    }
    
    @IBAction func handleAnyFileSelectFileButtonClicked(sender: NSButton) {
        let previouslySelectedPath = finalEditFilePath.stringValue
        
        anyFileFilePath.stringValue = ""
        anyFileCloudBackupFeedback.stringValue = ""
        
        if let fileURL = browseFiles() {
            anyFileFilePath.stringValue = fileURL.path
        }
        else {
            anyFileFilePath.stringValue = previouslySelectedPath
        }
    }
    
    func makeLocalBackup(sourceFilePath: URL, destinationFilePath: URL, onError: @escaping (String) -> Void, onCompletion: @escaping (String) -> Void) {
        do {
            try FileManager.default.copyItem(at: sourceFilePath, to: destinationFilePath)
            onCompletion("Backed up locally to " + destinationFilePath.path)
        } catch {
            onError("Failed to copy " + sourceFilePath.path + " to " + destinationFilePath.path + "\n" + error.localizedDescription)
        }
    }
    
    func logAndDisplayError(errorMessage: String) {
        print(errorMessage)
        DispatchQueue.main.async {
            self.originalRecordingCloudBackupFeedback.stringValue = errorMessage
        }
    }
    
    func authorize(backblazeInfo: BackblazeInfo, onError: @escaping (String) -> Void, onCompletion: @escaping (BackblazeAuthInfo) -> Void) {
        var request = URLRequest(url: URL(string: "https://api.backblazeb2.com/b2api/v3/b2_authorize_account")!)
        request.httpMethod = "GET"
        let basicAuthUserInfo = (backblazeInfo.backblazeApiKeyId + ":" + backblazeInfo.backblazeApiKey).data(using: .utf8)!.base64EncodedString()
        request.addValue("Basic \(basicAuthUserInfo)", forHTTPHeaderField: "Authorization")

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                onError("Failed to make authorization request to Backblaze to enable interaction.\n\(error)")
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                    if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "unauthorized" {
                        onError("Incorrect combination of application key ID and application key. Check your application key in the Backblaze Web UI and compare to the values in this application's preferences.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "unsupported" {
                        onError("Check your application key in the Backblaze Web UI -- can it be used to upload this file to this bucket?")
                    }
                    else if backblazeErrorResponse.status >= 500 {
                        onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                }
                else {
                    onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                }
                
                return
            }

            print(response.debugDescription)

            guard let data = data else {
                onError("Failed to authorize application with Backblaze.\nReceieved no data back in authorization response.")
                return
            }

            do {
                let auth = try JSONDecoder().decode(BackblazeAuthInfo.self, from: data)
                print(auth)
                onCompletion(auth)
            } catch  {
                onError("Failed to authorize application with Backblaze.\nFailed to decode data in authorization response.\n\(error)")
            }
        }

        task.resume()
    }

    func getBucketId(authInfo: BackblazeAuthInfo, bucketName: String, onError: @escaping (String) -> Void, onCompletion: @escaping (String) -> Void) {
        var request = URLRequest(url: URL(string: "b2api/v3/b2_list_buckets", relativeTo: authInfo.apiInfo.storageApi.apiUrl)!)
        request.httpMethod = "POST"
        request.addValue(authInfo.authorizationToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            // From https://www.backblaze.com/apidocs/b2-list-buckets,
            // "When bucketName is specified, the result will be a list
            // containing just this bucket, if it's present in the account, or
            // no buckets if the account does not have a bucket with this name."
            //
            // Since bucket names must be unique, we'll be able to take the
            // first bucket from the list of zero or one that is returned.
            let requestBody = try JSONSerialization.data(withJSONObject: ["accountId": authInfo.accountId, "bucketName": bucketName])
            
            let task = URLSession.shared.uploadTask(with: request, from: requestBody) { data, response, error in
                if let error = error {
                    onError("Failed to make request to Backblaze to list buckets in order to get the bucket ID.\n\(error)")
                    return
                }
                
                guard let httpResponse = response as? HTTPURLResponse,
                      (200...299).contains(httpResponse.statusCode) else {
                    if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                        if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "bad_auth_token" {
                            onError("Retry uploading.\nThe authorization token for the upload is not valid. Investigate if this happens very often at all.")
                        }
                        else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "expired_auth_token" {
                            onError("Retry uploading.\nThe authorization token for the upload is expired. Investigate if this happens very often at all.")
                        }
                        else if backblazeErrorResponse.status >= 500 {
                            onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                        }
                        else {
                            onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                        }
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                    
                    return
                }
                
                print(response.debugDescription)
                
                guard let data = data else {
                    onError("Failed to get bucket ID from Backblaze.\nReceieved no data back in list-buckets response.")
                    return
                }
                
                do {
                    let listBucketsReponse = try JSONDecoder().decode(ListBucketsResponse.self, from: data)
                    
                    guard let bucket = listBucketsReponse.buckets.first else {
                        onError("The given bucket wasn't found; no buckets were returned in the list of buckets.")
                        return
                    }
                    
                    onCompletion(bucket.bucketId)
                } catch  {
                    onError("Failed to get bucket ID from Backblaze.\nFailed to decode data in list-buckets response.\n\(error)")
                }
            }
            
            task.resume()
        } catch {
            onError(error.localizedDescription)
        }
    }

    /**
     * The Backblaze native API requires this means of uploading files less than 5GB.
     *
     * As per https://www.backblaze.com/docs/cloud-storage-create-large-files-with-the-native-api,
     * "the minimum part size is 5 MB except for the last part in a file which has a minimum size of 1 byte".
     */
    func getUploadUrl(authInfo: BackblazeAuthInfo, bucketId: String, onError: @escaping (String) -> Void, onCompletion: @escaping (UploadNonLargeFileUrlResponse) -> Void) {
        var urlComponents = URLComponents(string: URL(string: "b2api/v3/b2_get_upload_url", relativeTo: authInfo.apiInfo.storageApi.apiUrl)!.absoluteString)!
        urlComponents.queryItems = [
            URLQueryItem(name: "bucketId", value: bucketId)
        ]

        guard let url = urlComponents.url else {
            onError("Failed to construct URL to get the file-upload URL.")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.addValue(authInfo.authorizationToken, forHTTPHeaderField: "Authorization")

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                onError("Failed to make request to Backblaze to get the URL to which to upload the file.\n\(error)")
                return
            }

            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                    if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "bad_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is not valid. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "expired_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is expired. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 503 && backblazeErrorResponse.code == "service_unavailable" {
                        onError("Retry uploading. The Backblaze service was unavailable just now. Wait a little while and retry if it fails again.")
                    }
                    else if backblazeErrorResponse.status >= 500 {
                        onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                }
                else {
                    onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                }
                
                return
            }
            

            print(response.debugDescription)

            guard let data = data else {
                onError("Failed to get upload URL from Backblaze.\nReceieved no data back in get-upload-URL response.")
                return
            }

            do {
                let uploadUrlData = try JSONDecoder().decode(UploadNonLargeFileUrlResponse.self, from: data)
                print("uploadUrlData", uploadUrlData)
                onCompletion(uploadUrlData)
            } catch  {
                onError("Failed to get upload URL from Backblaze.\nFailed to decode data in get-upload-URL response.\n\(error)")
            }
        }

        task.resume()
    }

    func uploadFile(uploadAuthorizationToken: String, filePath: URL, uploadURL: URL, uploadedFileName: String, authorName: String, onError: @escaping (String) -> Void, onCompletion: @escaping (String) -> Void) {
        var request = URLRequest(url: uploadURL)
        request.httpMethod = "POST"
        request.addValue(uploadAuthorizationToken, forHTTPHeaderField: "Authorization")
        request.setValue("b2/x-auto", forHTTPHeaderField: "Content-Type")
        request.setValue(authorName.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed), forHTTPHeaderField: "X-Bz-Info-Author")
        request.setValue(uploadedFileName.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed), forHTTPHeaderField: "X-Bz-File-Name")
        request.setValue(sha1(url: filePath)!, forHTTPHeaderField: "X-Bz-Content-Sha1")
        
        print("upload-file request")
        print(request.debugDescription)
        print("headers")
        print(request.allHTTPHeaderFields?.debugDescription)
        print("method", request.httpMethod.debugDescription)
        
        let session = URLSession.init(configuration: .default, delegate: FileUploadDelegate(), delegateQueue: .current)
        // TODO: Providing a completion handler causes delegate methods not to be called (except authentication, which I'm not using).
        let task = session.uploadTask(with: request, fromFile: filePath) { data, response, error in
            if let error = error {
                onError("Failed to make request to Backblaze to upload the file.\n\(error)")
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                    if backblazeErrorResponse.status == 400 && backblazeErrorResponse.code == "auth_token_limit" {
                        onError("Retry uploading.\nThe authorization token for the upload has already been used. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "bad_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is not valid. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "expired_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is expired. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "unauthorized" {
                        onError("The authorization token for the upload doesn't work. Check your application key in the Backblaze Web UI -- can it be used to upload this file to this bucket?")
                    }
                    else if backblazeErrorResponse.status == 408 && backblazeErrorResponse.code == "request_timeout" {
                        onError("Retry uploading.\nThe Backblaze service took too long to read the uploaded file so it gave up. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 503 && backblazeErrorResponse.code == "service_unavailable" {
                        onError("Retry uploading. The Backblaze service was unavailable just now. Wait a little while and retry if it fails again.")
                    }
                    else if backblazeErrorResponse.status >= 500 {
                        onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                }
                else {
                    onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                }
                
                return
            }
            
            guard let data = data else {
                DispatchQueue.main.async {
                    onError("File was uploaded to Backblaze but no response data was provided.\nThat's really strange.\nThe file should be available in Backblaze.")
                }
                return
            }
            
            do {
                let uploadFileReponse = try JSONDecoder().decode(UploadNonLargeFileResponse.self, from: data)
                print("uploadFileReponse", uploadFileReponse)
                onCompletion(uploadFileReponse.fileName)
            } catch  {
                onError("Uploaded file to Backblaze but failed to decode data in upload response.\n\(error)" )
            }
        }
        
        task.resume()
    }
    
    func startLargeFileUpload(authInfo: BackblazeAuthInfo, bucketId: String, uploadedFileName: String, authorName: String, fileSha1: String, onError: @escaping (String) -> Void, onCompletion: @escaping (String) -> Void) {
        var request = URLRequest(url: URL(string: "/b2api/v3/b2_start_large_file", relativeTo: authInfo.apiInfo.storageApi.apiUrl)!)
        request.httpMethod = "POST"
        request.addValue(authInfo.authorizationToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            let requestBody = try JSONSerialization.data(withJSONObject: [
                "bucketId": bucketId,
                "fileName": uploadedFileName,
                "contentType": "b2/x-auto",
                "fileInfo": [
                    "large_file_sha1": fileSha1,
                    "author": authorName
                ]
            ])
            
            let task = URLSession.shared.uploadTask(with: request, from: requestBody) { data, response, error in
                if let error = error {
                    onError("Failed to make request to Backblaze to start a large-file upload.\n\(error)")
                    return
                }
                
                guard let httpResponse = response as? HTTPURLResponse,
                      (200...299).contains(httpResponse.statusCode) else {
                    if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                        if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "bad_auth_token" {
                            onError("Retry uploading.\nThe authorization token for the upload is not valid. Investigate if this happens very often at all.")
                        }
                        else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "expired_auth_token" {
                            onError("Retry uploading.\nThe authorization token for the upload is expired. Investigate if this happens very often at all.")
                        }
                        else if backblazeErrorResponse.status >= 500 {
                            onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                        }
                        else {
                            onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                        }
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                    
                    return
                }
                
                print(response.debugDescription)
                
                guard let data = data else {
                    onError("Failed to start large-file upload to Backblaze.\nReceieved no data back in start-upload response.")
                    return
                }
                
                do {
                    let response = try JSONDecoder().decode(StartLargeFileUploadResponse.self, from: data)
                    onCompletion(response.fileId)
                } catch  {
                    onError("Failed to start large-file upload to Backblaze.\nFailed to decode data in start-upload response.\n\(error)")
                }
            }
            
            task.resume()
        } catch {
            onError(error.localizedDescription)
        }
    }
    
    /**
     * The Backblaze native API requires this means of uploading files less than 5GB.
     *
     * As per https://www.backblaze.com/docs/cloud-storage-create-large-files-with-the-native-api,
     * "the minimum part size is 5 MB except for the last part in a file which has a minimum size of 1 byte".
     */
    func getLargeFileUploadPartUrl(authInfo: BackblazeAuthInfo, fileId: String, onError: @escaping (String) -> Void, onCompletion: @escaping (UploadLargeFilePartUrlResponse) -> Void) {
        var urlComponents = URLComponents(string: URL(string: "/b2api/v3/b2_get_upload_part_url", relativeTo: authInfo.apiInfo.storageApi.apiUrl)!.absoluteString)!
        urlComponents.queryItems = [
            URLQueryItem(name: "fileId", value: fileId)
        ]
        
        guard let url = urlComponents.url else {
            onError("Failed to construct URL to get the file-part-upload URL.")
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.addValue(authInfo.authorizationToken, forHTTPHeaderField: "Authorization")
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                onError("Failed to make request to Backblaze to get the URL to which to upload the file part.\n\(error)")
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                    if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "bad_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is not valid. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "expired_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is expired. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 503 && backblazeErrorResponse.code == "service_unavailable" {
                        onError("Retry uploading. The Backblaze service was unavailable just now. Wait a little while and retry if it fails again.")
                    }
                    else if backblazeErrorResponse.status >= 500 {
                        onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                }
                else {
                    onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                }
                
                return
            }
            
            print(response.debugDescription)
            
            guard let data = data else {
                onError("Failed to get upload URL from Backblaze.\nReceieved no data back in get-upload-part-URL response.")
                return
            }
            
            do {
                let uploadPartUrlData = try JSONDecoder().decode(UploadLargeFilePartUrlResponse.self, from: data)
                print("uploadPartUrlData", uploadPartUrlData)
                onCompletion(uploadPartUrlData)
            } catch  {
                onError("Failed to get upload-part URL from Backblaze.\nFailed to decode data in get-upload-part-URL response.\n\(error)")
            }
        }
        
        task.resume()
    }
    
    // TODO: Retry 5 times on failure, as per Backblaze documentation.
    //       I should retry anyway but 5 times is the recommended number, while 3 is common.
    func uploadLargeFilePart(uploadAuthorizationToken: String, uploadURL: URL, uploadPart: UploadPart, filePath: URL, onError: @escaping (String) -> Void, onCompletion: @escaping (Result<UploadedPart, Error>) -> Void) {
        var request = URLRequest(url: uploadURL)
        request.httpMethod = "POST"
        request.addValue(uploadAuthorizationToken, forHTTPHeaderField: "Authorization")
        request.addValue(String(uploadPart.partNumber), forHTTPHeaderField: "X-Bz-Part-Number")
        request.setValue(String(uploadPart.partSize), forHTTPHeaderField: "Content-Length")
        
        guard let partFileHandle = try? FileHandle(forReadingFrom: filePath) else {
            onError("Failed to read file \(filePath.path) to upload it to Backblaze")
            onCompletion(Result.failure(NSError(domain: "FileHandle(forReadingFrom: \(filePath.path)", code: -1)))
            return
        }
        
        defer {
            partFileHandle.closeFile()
        }
        print("Part \(uploadPart.partNumber) - Seeking to \(uploadPart.partStart)")
        partFileHandle.seek(toFileOffset: uploadPart.partStart)
        print("Part \(uploadPart.partNumber) - Reading to \(uploadPart.partStart + UInt64(uploadPart.partSize))")
        let part = partFileHandle.readData(ofLength: uploadPart.partSize)
        
        guard part.count > 0 else {
            onCompletion(Result.failure(NSError(domain: "Empty file-part: \(uploadPart) of file \(filePath.path)", code: -1)))
            return
        }
        
        print("Computing SHA1 of part \(uploadPart.partNumber)")
        let partSha1 = sha1(data: part)!
        print("SHA1 of part \(uploadPart.partNumber): \(partSha1)")
        request.setValue(partSha1, forHTTPHeaderField: "X-Bz-Content-Sha1")
        
        print("upload part \(uploadPart.partNumber) request")
        print(request.debugDescription)
        print("upload part \(uploadPart.partNumber) headers")
        print(request.allHTTPHeaderFields?.debugDescription)
        print("upload part \(uploadPart.partNumber) method", request.httpMethod.debugDescription)
        
        // TODO: Add delegate for progress reporting.
        let task = URLSession.shared.uploadTask(with: request, from: part) { data, response, error in
            if let error = error {
                onError("Failed to make request to Backblaze to upload part \(uploadPart.partNumber) of the file.\n\(error)")
                onCompletion(Result.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                    if backblazeErrorResponse.status == 400 && backblazeErrorResponse.code == "auth_token_limit" {
                        onError("Retry uploading.\nThe authorization token for the upload has already been used. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "bad_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is not valid. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "expired_auth_token" {
                        onError("Retry uploading.\nThe authorization token for the upload is expired. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "unauthorized" {
                        onError("The authorization token for the upload doesn't work. Check your application key in the Backblaze Web UI -- can it be used to upload this file to this bucket?")
                    }
                    else if backblazeErrorResponse.status == 408 && backblazeErrorResponse.code == "request_timeout" {
                        onError("Retry uploading.\nThe Backblaze service took too long to read the uploaded file so it gave up. Investigate if this happens very often at all.")
                    }
                    else if backblazeErrorResponse.status == 503 && backblazeErrorResponse.code == "service_unavailable" {
                        onError("Retry uploading. The Backblaze service was unavailable just now. Wait a little while and retry if it fails again.")
                    }
                    else if backblazeErrorResponse.status >= 500 {
                        onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                }
                else {
                    onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                }
                
                return
            }
            
            print(response.debugDescription)
            
            onCompletion(Result.success(UploadedPart(partNumber: uploadPart.partNumber, partSha1: partSha1)))
        }
        
        task.resume()
    }
    
    func finishLargeFileUpload(authInfo: BackblazeAuthInfo, fileId: String, partSha1Array: [String], onError: @escaping (String) -> Void, onCompletion: @escaping () -> Void) {
        var request = URLRequest(url: URL(string: "/b2api/v3/b2_finish_large_file", relativeTo: authInfo.apiInfo.storageApi.apiUrl)!)
        request.httpMethod = "POST"
        request.addValue(authInfo.authorizationToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            let requestBody = try JSONSerialization.data(withJSONObject: [
                "fileId": fileId,
                "partSha1Array": partSha1Array
            ])
            print("finishLargeFileUpload requestBody")
            print(try? JSONDecoder().decode(FinishRequestDebugStruct.self, from: requestBody))
            
            let task = URLSession.shared.uploadTask(with: request, from: requestBody) { data, response, error in
                if let error = error {
                    onError("Failed to make request to Backblaze to finish a large-file upload.\n\(error)")
                    return
                }
                
                guard let httpResponse = response as? HTTPURLResponse,
                      (200...299).contains(httpResponse.statusCode) else {
                    if let data = data, let backblazeErrorResponse = try? JSONDecoder().decode(BackblazeErrorResponse.self, from: data) {
                        if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "bad_auth_token" {
                            onError("Retry uploading.\nThe authorization token for the upload is not valid. Investigate if this happens very often at all.")
                        }
                        else if backblazeErrorResponse.status == 401 && backblazeErrorResponse.code == "expired_auth_token" {
                            onError("Retry uploading.\nThe authorization token for the upload is expired. Investigate if this happens very often at all.")
                        }
                        else if backblazeErrorResponse.status >= 500 {
                            onError("Retry uploading. Something went wrong with the Backblaze service. Wait a little while and retry if it fails again.")
                        }
                        else {
                            onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                        }
                    }
                    else {
                        onError("Failure response from Backblaze to request to upload the file.\n\(response.debugDescription)")
                    }
                    
                    return
                }
                
                print(response.debugDescription)
                
                guard let data = data else {
                    onError("Failed to finish large-file upload to Backblaze.\nReceieved no data back in finish-upload response.")
                    return
                }
                
                do {
                    let response = try JSONDecoder().decode(FinishLargeFileUploadResponse.self, from: data)
                    
                    guard response.action == "upload" else {
                        onError("Failed to finish large-file upload to Backblaze.\nThe requests to and responses from Backblaze all succeeded but the file's state is \"\(response.action)\", whereas it should be \"upload\".")
                        return
                    }
                    
                    onCompletion()
                } catch  {
                    onError("Failed to finish large-file upload to Backblaze.\nFailed to decode data in finish-upload response.\n\(error)")
                }
            }
            
            task.resume()
        } catch {
            onError(error.localizedDescription)
        }
    }
    
    func uploadNonLargeFileToBackblaze(backblazeAuthInfo: BackblazeAuthInfo, bucketId: String, uploadedFileName: String, authorName: String, filePath: URL, onError: @escaping (String) -> Void, onCompletion: @escaping (String) -> Void) {
        print("Uploading non-large file: \(filePath.path)")
        self.getUploadUrl(authInfo: backblazeAuthInfo, bucketId: bucketId, onError: onError, onCompletion: { uploadUrlData in
            self.uploadFile(uploadAuthorizationToken: uploadUrlData.authorizationToken, filePath: filePath, uploadURL: uploadUrlData.uploadUrl, uploadedFileName: uploadedFileName, authorName: authorName, onError: onError, onCompletion: onCompletion)
        })
    }
    
    func uploadLargeFileToBackblaze(backblazeAuthInfo: BackblazeAuthInfo, bucketId: String, uploadedFileName: String, authorName: String, filePath: URL, onError: @escaping (String) -> Void, onCompletion: @escaping (String) -> Void) {
        print("Uploading large file: \(filePath.path)")
        self.startLargeFileUpload(authInfo: backblazeAuthInfo, bucketId: bucketId, uploadedFileName: uploadedFileName, authorName: authorName, fileSha1: sha1(url: filePath)!, onError: onError, onCompletion: { fileId in
            let dispatchGroup = DispatchGroup()
            let numberOfUploadWorkers = max(ProcessInfo().activeProcessorCount - 1,
                                            1)
            print("numberOfUploadWorkers", numberOfUploadWorkers)
            let dispatchSemaphore = DispatchSemaphore(value: numberOfUploadWorkers)
            guard let uploadFileSizeInBytes = try? fileSizeInBytes(filePath: filePath.path) else {
                onError("Could not get size of file \(filePath.path) to compute parts to upload.\nTry again or restart and try again 🤷‍♂️")
                return
            }
            // We unwrap the value because we don't use the large-file upload for files smaller than the minimum part size.
            let regularPartSize = partSize(fileSize: uploadFileSizeInBytes,
                                           minimumPartSize: backblazeAuthInfo.apiInfo.storageApi.absoluteMinimumPartSize,
                                           recommendedPartSize: backblazeAuthInfo.apiInfo.storageApi.recommendedPartSize)!
            let uploadParts = uploadParts(fileSize: uploadFileSizeInBytes, regularPartSize: regularPartSize)
            print("uploadParts: \(uploadParts)")
            var uploadedParts: [UploadedPart] = []
            
            dispatchGroup.enter()
            
            print("Setting up work to be done when all group tasks have been done.")
            dispatchGroup.notify(queue: DispatchQueue.global(qos: .userInitiated)) {
                print("All group tasks have been done; in notify handler.")
                guard uploadParts.count == uploadedParts.count else {
                    print("Uploading some part of the file failed. Will not finish the upload.")
                    return
                }
                
                let partSha1Array = uploadedParts.sorted { $0.partNumber < $1.partNumber }.map { $0.partSha1 }
                print("partSha1Array: \(partSha1Array)")
                self.finishLargeFileUpload(authInfo: backblazeAuthInfo, fileId: fileId, partSha1Array: partSha1Array, onError: onError, onCompletion: { onCompletion(uploadedFileName) })
            }
            print("Did set up work to be done when all group tasks have been done.")
            
            print("Adding tasks to group, governed by semaphore.")
            for uploadPart in uploadParts {
                dispatchSemaphore.wait()
                dispatchGroup.enter()
                
                self.getLargeFileUploadPartUrl(authInfo: backblazeAuthInfo, fileId: fileId, onError: onError, onCompletion: { uploadPartUrlData in
                    self.uploadLargeFilePart(uploadAuthorizationToken: uploadPartUrlData.authorizationToken, uploadURL: uploadPartUrlData.uploadUrl, uploadPart: uploadPart, filePath: filePath, onError: onError, onCompletion: { result in
                        print("Upload part \(uploadPart.partNumber) result:\n\(result)")
                        
                        if case .success(let uploadedPart) = result {
                            uploadedParts.append(uploadedPart)
                        }
                        
                        dispatchSemaphore.signal()
                        dispatchGroup.leave()
                    })
                })
            }
            print("Did add tasks to group, governed by semaphore.")
            
            dispatchGroup.leave()
        })
    }

    func uploadToBackblaze(filePath: URL, uploadedFileName: String, onError: @escaping (String) -> Void, onCompletion: @escaping (String) -> Void) {
        let temp = tempFilePath()
        let makeZipArchiveError = makeZipArchive(inputPath: filePath, outputPath: temp)
        
        guard makeZipArchiveError == nil else {
            onError("Could not make zip file of original recording to upload: \(makeZipArchiveError!)")
            return
        }
        
        guard let uploadFileSizeInBytes = try? fileSizeInBytes(filePath: filePath.path) else {
            onError("Could not get size of file \(filePath.path) to determine which upload method to use.\nTry again or restart and try again 🤷‍♂️")
            return
        }
        
        guard let backblazeInfo = getBackblazeInfo() else { return }
        
        self.authorize(backblazeInfo: backblazeInfo, onError: onError, onCompletion: { backblazeAuthInfo in
            self.getBucketId(authInfo: backblazeAuthInfo, bucketName: backblazeInfo.backblazeBucketName, onError: onError, onCompletion: { bucketId in
                let uploadFn = uploadFileSizeInBytes < backblazeAuthInfo.apiInfo.storageApi.absoluteMinimumPartSize
                ? self.uploadNonLargeFileToBackblaze
                : self.uploadLargeFileToBackblaze
                
                uploadFn(backblazeAuthInfo, bucketId, uploadedFileName, backblazeInfo.authorName, temp, onError, onCompletion)
            })
        })
    }
    
    @IBAction func handleBackupOriginalRecordingButtonClicked(sender: NSButton) {
        if self.originalRecordingFilePath.stringValue.isEmpty {
            self.originalRecordingLocalBackupFeedback.stringValue = "Select file to back up."
            return
        }
        
        let originalRecordingFilePath = URL(fileURLWithPath: self.originalRecordingFilePath.stringValue)
        let localBackupFilePath = URL(
            fileURLWithPath: appendToFileNameKeepingExtension(append: "__original", to: originalRecordingFilePath),
            relativeTo: originalRecordingFilePath.deletingLastPathComponent()
        ).standardizedFileURL
        print("localBackupFilePath", localBackupFilePath)
        print("localBackupFilePath.path", localBackupFilePath.path)
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.makeLocalBackup(sourceFilePath: originalRecordingFilePath,
                                 destinationFilePath: localBackupFilePath,
                                 onError: { message in
                print(message)
                DispatchQueue.main.async {
                    self.originalRecordingLocalBackupFeedback.stringValue = message
                    self.originalRecordingLocalBackupFeedback.textColor = NSColor.red
                }
            },
                                 onCompletion: { message in
                DispatchQueue.main.async {
                    self.originalRecordingLocalBackupFeedback.stringValue = message
                    self.originalRecordingLocalBackupFeedback.textColor = NSColor.green
                }
            })
        }
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.uploadToBackblaze(filePath: originalRecordingFilePath,
                                   uploadedFileName: localBackupFilePath.lastPathComponent,
                                   onError: { message in
                print(message)
                DispatchQueue.main.async {
                    self.originalRecordingCloudBackupFeedback.stringValue = message
                    self.originalRecordingCloudBackupFeedback.textColor = NSColor.red
                }
            },
                                   onCompletion: { uploadedFileName in
                DispatchQueue.main.async {
                    self.originalRecordingCloudBackupFeedback.stringValue = "Backed up in Backblaze."
                    self.originalRecordingCloudBackupFeedback.textColor = NSColor.green
                }
            })
        }
    }
    
    @IBAction func handleBackupFinalEditButtonClicked(sender: NSButton) {
        if self.finalEditFilePath.stringValue.isEmpty {
            self.finalEditCloudBackupFeedback.stringValue = "Select file to back up."
            return
        }
        
        let finalEditFilePath = URL(fileURLWithPath: self.finalEditFilePath.stringValue)
        let formattedNow = ISO8601DateFormatter().string(from: Date())
        let backupFileName = appendToFileNameKeepingExtension(append: formattedNow, to: finalEditFilePath)
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.uploadToBackblaze(filePath: finalEditFilePath,
                                   uploadedFileName: backupFileName,
                                   onError: { message in
                print(message)
                DispatchQueue.main.async {
                    self.finalEditCloudBackupFeedback.stringValue = message
                    self.finalEditCloudBackupFeedback.textColor = NSColor.red
                }
            },
                                   onCompletion: { uploadedFileName in
                DispatchQueue.main.async {
                    self.finalEditCloudBackupFeedback.stringValue = "Backed up in Backblaze."
                    self.finalEditCloudBackupFeedback.textColor = NSColor.green
                }
            })
        }
    }
    
    @IBAction func handleBackupAudioTrackButtonClicked(sender: NSButton) {
        if self.audioTrackFilePath.stringValue.isEmpty {
            self.audioTrackCloudBackupFeedback.stringValue = "Select file to back up."
            return
        }
        
        let audioTrackFilePath = URL(fileURLWithPath: self.audioTrackFilePath.stringValue)
        let backupFileName = audioTrackFilePath.lastPathComponent
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.uploadToBackblaze(filePath: audioTrackFilePath,
                                   uploadedFileName: backupFileName,
                                   onError: { message in
                print(message)
                DispatchQueue.main.async {
                    self.audioTrackCloudBackupFeedback.stringValue = message
                    self.audioTrackCloudBackupFeedback.textColor = NSColor.red
                }
            },
                                   onCompletion: { uploadedFileName in
                DispatchQueue.main.async {
                    self.audioTrackCloudBackupFeedback.stringValue = "Backed up in Backblaze."
                    self.audioTrackCloudBackupFeedback.textColor = NSColor.green
                }
            })
        }
    }
    
    @IBAction func handleBackupAnyFileButtonClicked(sender: NSButton) {
        if self.anyFileFilePath.stringValue.isEmpty {
            self.anyFileCloudBackupFeedback.stringValue = "Select file to back up."
            return
        }
        
        let anyFileFilePath = URL(fileURLWithPath: self.anyFileFilePath.stringValue)
        let backupFileName = anyFileFilePath.lastPathComponent
        
        DispatchQueue.global(qos: .userInitiated).async {
            self.uploadToBackblaze(filePath: anyFileFilePath,
                                   uploadedFileName: backupFileName,
                                   onError: { message in
                print(message)
                DispatchQueue.main.async {
                    self.anyFileCloudBackupFeedback.stringValue = message
                    self.anyFileCloudBackupFeedback.textColor = NSColor.red
                }
            },
                                   onCompletion: { uploadedFileName in
                DispatchQueue.main.async {
                    self.anyFileCloudBackupFeedback.stringValue = "Backed up in Backblaze."
                    self.anyFileCloudBackupFeedback.textColor = NSColor.green
                }
            })
        }
    }
}
