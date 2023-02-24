import reactLogo from './assets/react.svg'
import './App.css'
import keystore from 'keystore-idb'
import {CharSize, CryptoSystem, HashAlg} from "keystore-idb/types";
import axios from "axios";

const url = "http://localhost:8080/"

function App() {
    async function run() {
        await keystore.clear()

        const ks1 = await keystore.init({
            storeName: 'keystore',
            type: CryptoSystem.RSA,
            rsaSize: 2048,
            hashAlg: HashAlg.SHA_512,
            charSize: CharSize.B8
        })

        const msg = "Hello world1"

        // exchange keys and write keys are separate because of the Web Crypto API
        const writeKey1 = await ks1.publicWriteKey()

        // these keys get exported as strings
        console.log('writeKey1: ', writeKey1)

        const sig = await ks1.sign(msg)
        const valid = await ks1.verify(msg, sig, writeKey1)
        console.log('sig: ', sig)
        console.log('valid: ', valid)
        // Make request to server via axios
        await axios.post(url, {
            pubKey: writeKey1,
            data: msg,
            sig: sig
        })


    }

    return (
        <div className="App">
            <div>
                <a href="https://vitejs.dev" target="_blank">
                    <img src="/vite.svg" className="logo" alt="Vite logo"/>
                </a>
                <a href="https://reactjs.org" target="_blank">
                    <img src={reactLogo} className="logo react" alt="React logo"/>
                </a>
            </div>
            <h1>Vite + React</h1>
            <div className="card">
                <button onClick={async () => await run()}>
                    RUN
                </button>
                <p>
                    Edit <code>src/App.tsx</code> and save to test HMR
                </p>
            </div>
            <p className="read-the-docs">
                Click on the Vite and React logos to learn more
            </p>
        </div>
    )
}

export default App
