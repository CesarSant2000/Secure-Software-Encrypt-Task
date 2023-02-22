import {Button, Divider, FormControl, Grid, InputLabel, List, ListItem, MenuItem, Typography} from "@mui/material";
import Box from '@mui/material/Box';
import TextField from '@mui/material/TextField';
import {useEffect, useState} from "react";
import Select, {SelectChangeEvent} from '@mui/material/Select';
import {useForm, SubmitHandler} from "react-hook-form";

const SEAL = require('node-seal')

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

};
export default function EncryptTask() {
    const [publicKey, setPublicKey] = useState('')
    const [secretKey, setSecretKey] = useState('')
    const {register, handleSubmit, watch, formState: {errors}} = useForm<Inputs>();
    const onSubmit: SubmitHandler<Inputs> = data => {
        console.log(data);
        alert(JSON.stringify(data));
    }

    useEffect(() => {
            dataOperations()
        }
        , [])

    const dataOperations = async () => {
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

        const encoder = seal.BatchEncoder(context)
        const keyGenerator = seal.KeyGenerator(context)
        const publicKey = keyGenerator.createPublicKey()
        setPublicKey(publicKey.save())
        const secretKey = keyGenerator.secretKey()
        setSecretKey(secretKey.save())
        const encryptor = seal.Encryptor(context, publicKey)
        const decryptor = seal.Decryptor(context, secretKey)
        const evaluator = seal.Evaluator(context)

        // Create data to be encrypted
        const array = Int32Array.from([1, 2, 3, 4, 5])
        // Encode the Array
        const plainText = encoder.encode(array)

        // Encrypt the PlainText
        const cipherText = encryptor.encrypt(plainText)

        // Add the CipherText to itself and store it in the destination parameter (itself)
        evaluator.add(cipherText, cipherText, cipherText) // Op (A), Op (B), Op (Dest)

        // Or create return a new cipher with the result (omitting destination parameter)
        // const cipher2x = evaluator.add(cipherText, cipherText)

        // Decrypt the CipherText
        const decryptedPlainText = decryptor.decrypt(cipherText)

        // Decode the PlainText
        const decodedArray = encoder.decode(decryptedPlainText)

        console.log('decodedArray', decodedArray)
    }

    const [operation, setOperation] = useState(10);

    const handleChange = async (event: SelectChangeEvent) => {
        await setOperation(parseInt(event.target.value));

    };

    return (
        <Grid container justifyContent={"center"} sx={
            {
                height: '100%',
                minHeight: '100vh',
                maxHeight: '?',
            }
        }>
            <Grid item xs={6} md={6} bgcolor={"antiquewhite"} padding={"3rem"} margin={"4rem"} justifyContent={"center"}
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
                                    {publicKey}
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
                                    {secretKey}
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
                                <MenuItem value={20}>Sumar</MenuItem>
                                <MenuItem value={30}>Sumar plano</MenuItem>
                                <MenuItem value={40}>Multiplicar</MenuItem>
                                <MenuItem value={50}>Multiplicar plano</MenuItem>
                            </Select>
                        </FormControl>
                        <form onSubmit={handleSubmit(onSubmit)}>
                            {operation === 10 &&
                                <TextField id="plain_text_crypt" label="Texto plano"
                                           variant="outlined" {...register("plain_text_crypt")}/>
                            }
                            {operation === 20 &&
                                <>
                                    <TextField id="crypt_text_sum1" label="Texto encriptado 1"
                                               variant="outlined" {...register("crypt_text_sum1")}/>
                                    <TextField id="crypt_text_sum2" label="Texto encriptado 2"
                                               variant="outlined" {...register("crypt_text_sum2")}/>
                                </>
                            }
                            {operation === 30 &&
                                <>
                                    <TextField id="crypt_text_sum3" label="Texto encriptado"
                                               variant="outlined" {...register("crypt_text_sum3")}/>
                                    <TextField id="plain_text_sum4" label="Texto plano"
                                               variant="outlined" {...register("plain_text_sum4")}/>
                                </>
                            }
                            {operation === 40 &&
                                <>
                                    <TextField id="crypt_text_mult1" label="Texto encriptado 1"
                                               variant="outlined" {...register("crypt_text_mult1")}/>
                                    <TextField id="crypt_text_mult2" label="Texto encriptado 2"
                                               variant="outlined" {...register("crypt_text_mult2")}/>
                                </>
                            }
                            {operation === 50 &&
                                <>
                                    <TextField id="crypt_text_mult3" label="Texto encriptado"
                                               variant="outlined" {...register("crypt_text_mult3")}/>
                                    <TextField id="plain_text_mult4" label="Texto plano"
                                               variant="outlined" {...register("plain_text_mult4")}/>
                                </>
                            }
                            {/*{errors.plain_text_crypt && <span>This field is required</span>}*/}
                            <Button variant="contained" type={"submit"}>Ejecutar</Button>
                        </form>
                    </Box>

                </Grid>
            </Grid>
        </Grid>
    )
}
