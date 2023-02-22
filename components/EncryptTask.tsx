import {Button, Divider, FormControl, Grid, InputLabel, List, ListItem, MenuItem, Typography} from "@mui/material";
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import {useEffect, useState} from "react";
import Select, {SelectChangeEvent} from '@mui/material/Select';
import {useForm, SubmitHandler} from "react-hook-form";
import styles from '../styles/Form.module.css'

const SEAL = require('node-seal')
const seal = await SEAL()
const schemeType = seal.SchemeType.bfv
const securityLevel = seal.SecurityLevel.tc128
const polyModulusDegree = 4096
const bitSizes = [36, 36, 37]
const bitSize = 20
const parms = seal.EncryptionParameters(schemeType)
// Set the PolyModulusDegree
parms.setPolyModulusDegree(polyModulusDegree)

// Create a suitable set of CoeffModulus primes
parms.setCoeffModulus(
    seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
)

// Set the PlainModulus to a prime of bitSize 20.
parms.setPlainModulus(
    seal.PlainModulus.Batching(polyModulusDegree, bitSize)
)

const context = seal.Context(
    parms, // Encryption Parameters
    true, // ExpandModChain
    securityLevel // Enforce a security level
)

if (!context.parametersSet()) {
    throw new Error(
        'Could not set the parameters in the given context. Please try different encryption parameters.'
    )
}
const encoder = seal.BatchEncoder(context);
const keyGenerator = seal.KeyGenerator(context);
const publicKey = keyGenerator.createPublicKey();
const secretKey = keyGenerator.secretKey();
const encryptor = seal.Encryptor(context, publicKey);
const decryptor = seal.Decryptor(context, secretKey);
const evaluator = seal.Evaluator(context);

type Inputs = {
    plain_text_crypt?: string;
    crypt_text_sum1?: string;
    crypt_text_sum2?: string;
    crypt_text_sum3?: string;
    plain_text_sum4?: string;
    crypt_text_mult1?: string;
    crypt_text_mult2?: string;
    crypt_text_mult3?: string;
    plain_text_mult4?: string;
    crypt_text_decrypt?: string;
};
export default function EncryptTask() {
    const [result, setResult] = useState('')
    const {register, handleSubmit, formState: {errors}} = useForm<Inputs>();
    const [operation, setOperation] = useState(10);
    const [keyPublic, setKeyPublic] = useState('')
    const [keySecret, setKeySecret] = useState('')
    const [cypherText, setCypherText] = useState(null)

    useEffect(() => {
            dataOperations().then().catch((e: any) => {
                    console.log(e)
                }
            )
        }
        , [])

    const dataOperations = async () => {
        setKeyPublic(publicKey.save())
        setKeySecret(secretKey.save())
        // Create data to be encrypted
        const array = Int32Array.from([1, 2, 3, 4, 5])
        // Encode the Array
        const plainText = encoder.encode(array)

        // Encrypt the PlainText
        const cipherText = encryptor.encrypt(plainText)
        setCypherText(cipherText)

        // Add the CipherText to itself and store it in the destination parameter (itself)
        evaluator.add(cipherText, cipherText, cipherText) // Op (A), Op (B), Op (Dest)

        // Or create return a new cipher with the result (omitting destination parameter)
        // const cipher2x = evaluator.add(cipherText, cipherText)

        // Decrypt the CipherText
        const decryptedPlainText = decryptor.decrypt(cipherText)

        // Decode the PlainText
        const decodedArray = encoder.decode(decryptedPlainText)
    }


    const handleChange = async (event: SelectChangeEvent) => {
        await setOperation(parseInt(event.target.value));
    };

    const onSubmit: SubmitHandler<Inputs> = data => {
        switch (operation) {
            case 10:
                const tempText = data.plain_text_crypt || ''
                const tempArray = tempText.split(',')
                const tempArrayInt = tempArray.map((item) => {
                        return parseInt(item)
                    }
                )
                const array = Int32Array.from(tempArrayInt)
                // Encode the Array
                const plainText = encoder.encode(array)
                // Encrypt the PlainText
                const cipherText = encryptor.encrypt(plainText)
                console.log('ciphertext', cipherText.save())
                setResult(cipherText.save())
                setCypherText(cipherText)
                break;
            case 20:
                setResult('20')
                break;
            case 30:
                const tempTextSum = data.plain_text_sum4 || ''
                const tempArraySum = tempTextSum.split(',')
                const tempArrayIntSum = tempArraySum.map((item) => {
                        return parseInt(item)
                    }
                )
                const arraySum = Int32Array.from(tempArrayIntSum)
                const plainTextSum = encoder.encode(arraySum)
                const tempResult = evaluator.addPlain(cypherText, plainTextSum)
                console.log('Sum result', tempResult)
                setResult(tempResult.save())
                setCypherText(tempResult)
                break;
            case 40:
                setResult('40')
                break;
            case 50:
                const tempTextMult = data.plain_text_mult4 || ''
                const tempArrayMult = tempTextMult.split(',')
                const tempArrayIntMult = tempArrayMult.map((item) => {
                        return parseInt(item)
                    }
                )
                const arrayMult = Int32Array.from(tempArrayIntMult)
                const plainTextMult = encoder.encode(arrayMult)
                const tempResultMult = evaluator.multiplyPlain(cypherText, plainTextMult)
                console.log('Mult result', tempResultMult)
                setResult(tempResultMult.save())
                setCypherText(tempResultMult)
                break;
            case 60:
                if (result && result !== '' && cypherText) {
                    const decryptedPlainText = decryptor.decrypt(cypherText)
                    const decodedArray = encoder.decode(decryptedPlainText)
                    console.log('decodedArray', decodedArray)
                    const tempResult = decodedArray.toString()
                    setResult(tempResult)
                    setCypherText(null)
                }else{
                    alert('No se ha realizado ninguna operación')
                }
                break;
            default:
                setResult('0')
        }
    }

    return (
        <>

            <Grid container justifyContent={"center"} sx={
                {
                    height: '100%',
                    minHeight: '100vh',
                    maxHeight: '?',
                }
            }>
                <Grid item xs={6} md={6} bgcolor={"antiquewhite"} padding={"3rem"} margin={"4rem"}
                      justifyContent={"center"}
                      alignContent={"center"} borderRadius={"1rem"} alignItems={"center"}
                >
                    <Grid item xs={12} md={12} justifyContent={"center"} alignContent={"center"}>
                        <Typography variant={"h5"} align={"center"} fontWeight={"bold"}>
                            HERRAMIENTA DE ENCRIPTACIÓN USANDO MICROSOFT SEAL
                        </Typography>
                        <Grid width={"100%"} paddingY={"1rem"}>
                            <List>
                                <Divider/>
                                <ListItem>
                                    <Typography variant={"h6"} width={"100%"} fontWeight={"bold"}>
                                        Clave publica
                                    </Typography>
                                </ListItem>
                                <ListItem>
                                    <Typography variant={"body1"} width={"100%"} fontWeight={"bold"}
                                                sx={{
                                                    // hide the overflow
                                                    overflow: 'hidden',
                                                    textOverflow: 'ellipsis',
                                                }}
                                    >
                                        {keyPublic}
                                    </Typography>
                                </ListItem>
                                <Divider/>
                                <ListItem>
                                    <Typography variant={"h6"} width={"100%"} fontWeight={"bold"}>
                                        Clave privada
                                    </Typography>
                                </ListItem>
                                <ListItem>
                                    <Typography variant={"body1"} width={"100%"} fontWeight={"bold"}
                                                sx={{
                                                    // hide the overflow
                                                    overflow: 'hidden',
                                                    textOverflow: 'ellipsis',
                                                }}
                                    >
                                        {keySecret}
                                    </Typography>
                                </ListItem>
                                <Divider/>
                                <ListItem>
                                    <Typography color={"blue"} variant={"h6"} width={"100%"} fontWeight={"bold"}>
                                        Resultado
                                    </Typography>
                                </ListItem>
                                <ListItem>
                                    <Typography color={"blue"} variant={"body1"} width={"100%"} fontWeight={"bold"}
                                                sx={{
                                                    // hide the overflow
                                                    overflow: 'hidden',
                                                    textOverflow: 'ellipsis',
                                                }}
                                    >
                                        {result}
                                    </Typography>
                                </ListItem>
                                <Divider/>
                            </List>
                        </Grid>
                        <Box
                            component="form"
                            sx={{
                                '& > :not(style)': {m: 3, width: '90%'},
                            }}
                            noValidate
                            autoComplete="off"
                            textAlign={"center"}
                            padding={"1rem"}
                        >
                            <FormControl fullWidth>
                                <InputLabel id="demo-simple-select-label">Operacion</InputLabel>
                                <Select
                                    labelId="demo-simple-select-label"
                                    id="demo-simple-select"
                                    value={operation.toString()}
                                    label="Operacion"
                                    onChange={handleChange}
                                >
                                    <MenuItem value={10}>Encriptar</MenuItem>
                                    <MenuItem value={30}>Sumar plano</MenuItem>
                                    <MenuItem value={50}>Multiplicar plano</MenuItem>
                                    <MenuItem value={60}>Desencriptar</MenuItem>
                                </Select>
                            </FormControl>
                            <>
                                {operation === 10 &&
                                    <>
                                        <TextField id="plain_text_crypt" label="Texto plano"
                                                   variant="outlined" {...register("plain_text_crypt", {required: true})}/>
                                        {errors.plain_text_crypt && <span>El campo texto plano es obligatorio</span>}
                                    </>
                                }
                                {operation === 20 &&
                                    <>
                                        <TextField id="crypt_text_sum1" label="Texto encriptado 1"
                                                   variant="outlined" {...register("crypt_text_sum1", {required: true})}/>
                                        {errors.crypt_text_sum1 &&
                                            <span>El campo texto encriptado 1 es obligatorio</span>}
                                        <TextField id="crypt_text_sum2" label="Texto encriptado 2"
                                                   variant="outlined" {...register("crypt_text_sum2", {required: true})}/>
                                        {errors.crypt_text_sum2 &&
                                            <span>El campo texto encriptado 2 es obligatorio</span>}
                                    </>
                                }
                                {operation === 30 &&
                                    <>
                                        <TextField id="plain_text_sum4" label="Texto plano"
                                                   variant="outlined" {...register("plain_text_sum4", {required: true})}/>
                                        {errors.plain_text_sum4 && <span>El campo texto plano es obligatorio</span>}
                                    </>
                                }
                                {operation === 40 &&
                                    <>
                                        <TextField id="crypt_text_mult1" label="Texto encriptado 1"
                                                   variant="outlined" {...register("crypt_text_mult1", {required: true})}/>
                                        {errors.crypt_text_mult1 &&
                                            <span>El campo texto encriptado 1 es obligatorio</span>}
                                        <TextField id="crypt_text_mult2" label="Texto encriptado 2"
                                                   variant="outlined" {...register("crypt_text_mult2", {required: true})}/>
                                        {errors.crypt_text_mult2 &&
                                            <span>El campo texto encriptado 2 es obligatorio</span>}
                                    </>
                                }
                                {operation === 50 &&
                                    <>
                                        <TextField id="plain_text_mult4" label="Texto plano"
                                                   variant="outlined" {...register("plain_text_mult4", {required: true})}/>
                                        {errors.plain_text_mult4 && <span>El campo texto plano es obligatorio.</span>}
                                    </>
                                }
                            </>
                            {/*{errors.plain_text_crypt && <span>This field is required</span>}*/}
                        </Box>
                        <form onSubmit={handleSubmit(onSubmit)}>
                            <div className={styles.buttonHolder}>
                                <Button variant="contained" type={"submit"}>Ejecutar</Button>
                            </div>
                        </form>
                    </Grid>
                </Grid>
            </Grid>
        </>
    )
}
