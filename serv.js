require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//config JSON
app.use(express.json())

//model
const User = require('./model/User')

//Route - rota publica
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id

    // checar se o usuario existe
    const user = await User.findById(id, '-senha')

    if(!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado'})
    }

    res.status(202).json({ user })
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({ msg: "Acesso negado!"}) 
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error) {
        res.status(400).json({ msg: "Token inválido!"})
    }
}

// Registrar usuario
app.post('/auth/register', async (req, res) => {

    const {nome, email, senha, confirmasenha} = req.body

    //validação
    if(!nome) {
        return res.status(422).json({ msg: 'Usuário obrigatório'})
    }
    if(!email) {
        return res.status(422).json({ msg: 'E-mail obrigatório'})
    }
    if(!senha) {
        return res.status(422).json({ msg: 'Senha obrigatória '})
    }
    if(senha != confirmasenha) {
        return res.status(422).json({ msg: 'A senha de confirmação precisam ser iguais'})
    }

//chegar se o usuario existe
const userExists = await User.findOne({ email: email })

if (userExists) {
    return res.status(422).json({ msg: 'Por favor, utilize outro e-mail!' })
}

//criar senha
    const salt = await bcrypt.genSalt(12)
    const senhaHash = await bcrypt.hash(senha, salt)

    // criar usuario
    const user = new User({
        nome,
        email,
        senha: senhaHash,
    })

    try {

        await user.save()

        res.status(201).json({ msg:'Usuário criado com sucesso!'})

    } catch(error) {
        console.log(error)
        res
        .status(500)
        .json({
            msg: "Erro inesperado"
        })
    }
})

//login usuario
app.post("/auth/login", async (req, res) => {
    const { email, senha } = req.body

    // validação
    if(!email) {
        return res.status(422).json({ msg: 'E-mail obrigatório'})
    }
    if(!senha) {
        return res.status(422).json({ msg: 'Senha obrigatória '})
    }

//senhar se o usuario exist
const user = await User.findOne({ email: email })

    if(!user){
        return res.status(404).json({ msg: 'Usuário não encontrato'})
    }

// chegar senha
const checkSenha = await bcrypt.compare(senha, user.senha)

    if(!checkSenha){
        return res.status(422).json({ msg: 'Senha inválida!'})
    }

    try{

        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token })

    }catch (err) {
        res
        .status(500)
        .json({
            msg: "Erro inesperado"
        })
    }

})


//Credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.ppqxg27.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
    console.log('conectou!')
    app.listen(3000)
})
.catch((err) => console.log(err))

