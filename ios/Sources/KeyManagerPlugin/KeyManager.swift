import Foundation

@objc public class KeyManager: NSObject {
    @objc public func echo(_ value: String) -> String {
        print(value)
        return value
    }
}
