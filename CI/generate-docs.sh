gem install jazzy

jazzy \
--author "Virgil Security" \
--author_url "https://virgilsecurity.com/" \
--xcodebuild-arguments -scheme,"VirgilSDKKeyknox macOS" \
--module "VirgilSDKKeyknox" \
--output "${OUTPUT}" \
--hide-documentation-coverage \
--theme apple
