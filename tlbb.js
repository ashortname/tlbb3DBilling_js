//配置服务器
const express = require('express');
const app = express();
const path = require('path');
const bodyParser = require("body-parser");
const ejs = require('ejs');
const session = require('express-session');
//用于获取时间
const moment = require('moment');
//引用加解密
const crypto = require('crypto');
//数据库
const mysql = require('mysql');
//配置文件
const config = require('./tconfig');
//读取文件
const fs = require("fs");
const readline = require('readline');
const rootPath = __dirname + '/static';
//memcache
const memcache = require('memcached');

app.set('views', rootPath);
app.set('view engine', 'html'); // 设置解析模板文件类型：这里为html文件
app.engine('html', ejs.__express); // 使用ejs引擎解析html文件中ejs语法

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
// 使用 session 中间件
app.use(session({
    secret :  'secret', // 对session id 相关的cookie 进行签名
    resave : true,
    saveUninitialized: false, // 是否保存未初始化的会话
    cookie : {
        maxAge : 1000 * 60 * 5, // 设置 session 的有效时间，单位毫秒
    },
}));
//直接引用的
app.use(express.static(path.join(__dirname, './static/static')));

//设置跨域访问
app.all('*', function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "X-Requested-With");
  res.header("Access-Control-Allow-Methods", "POST,GET,OPTIONS");
  res.header("X-Powered-By", '3.2.1');
  next();
});

class TDES
{
    constructor(key) {
        this.key = key
    }
	
/**
 * 加密方法
 * @param key 加密key
 * @param iv       向量
 * @param data     需要加密的数据
 * @returns string
 */
	Tencrypt(data){
		var cipher = crypto.createCipheriv('des-cbc', this.key, "");
		var crypted = cipher.update(data, 'utf8', 'binary');
		crypted += cipher.final('binary');
		crypted = new Buffer(crypted, 'binary').toString('hex');
		return crypted;
};

/**
 * 解密方法
 * @param key      解密的key
 * @param iv       向量
 * @param crypted  密文
 * @returns string
 */
	Tdecrypt(crypted){
		crypted = new Buffer.from(crypted, 'utf8').toString('binary');
		crypted = this.getASC(crypted);		
		var decipher = crypto.createDecipheriv('des-ecb', this.key, "");
		var decoded = decipher.update(crypted, 'binary', 'utf8');
		decoded += decipher.final('utf8');
		return decoded;
};

	getASC(strhex){
	var res = "";
	for(var i = 0; i < strhex.length; i+=2)
	{
		res += String.fromCharCode(parseInt(strhex.substr(i, 2), 16));
	}
	return res;
};
}

/***
*获取服务器列表
*/
/*app.get('/tianlong3D/conf/serverlist/serverlist.txt', function(req, res){
	res.sendFile(rootPath + '/tianlong3D/conf/serverlist/serverlist.txt');
	res.end();
});*/

/***
*billing验证
*/
app.post('/billing', function(req, res){
	let tag = req.headers.tag,
		opcode = req.headers.opcode,
		channelid = req.headers.channelid,
		data = JSON.parse(req.body.data),
		des = new TDES("cyou-mrd"),
		result = {};
	if(opcode == 10001)
	{
		let validateInfo = JSON.parse(des.Tdecrypt(data['validateInfo']));
		let oid = validateInfo['oid'],
			token = validateInfo['token'];
		result = {
			'tag' : tag,
			'opcode' : opcode,
			'state' : 200,
			'datauserid' : oid,
			'data' : {
				'status' : 1,
				'token' : token,
				'accesstoken' : token,
                'oid' : oid,
                'userid' : oid,
			},
			'channelId' : channelid
		};
		console.log("oid [%s] billing at %s", oid, moment().format('YYYY-MM-DD HH:mm:ss'));
		res.status(200).end(JSON.stringify(result));
	}else{
		let	con = mysql.createConnection(config.SQLCharge),
			pid = data['role_id'],
			getSQL = "select * from charge where roleid=? limit 1",
			getParam = [pid],
			upSQL = "update charge set num=0 where roleid=?";
		con.connect();
		con.query(getSQL, getParam, function(err, result){
			if(err)
			{
				console.log(err.message);
				res.status(200).end("error");
				return;
			}			
			if(result)
			{
				if(result.length > 0)
				{
					let num = result[0].num,
						con1 = mysql.createConnection(config.SQLCharge);
					
					con1.connect();
					con1.query(upSQL, getParam, function(err, result){
						let seq = data['seq_no'],
							Tresult = {
								'tag' : tag,
								'opcode' : opcode,
								'state' : 200,
								'data' : {
									'seq_no' : seq,
									'seq_times' : 1,
									'success' : 1,
									'status' : 1,
									'coin' : num,
									'totalcoin' : num,
									'ischarge' : 1,
									'list' : {}
								}
							};
						res.status(200).end(JSON.stringify(Tresult));
					});
					con1.end();
				}
				else
				{
					res.status(200).end("error")
				}
			}			
	});
		con.end();
	}
});

/***
*用户登录
*/
app.post('/login.php', function(req, res){
	//res.header("Content-Type", "text/html;charset=utf-8");
	let name = req.body.loginName,
		pass = req.body.loginPwd,
		con = mysql.createConnection(config.SQLAcc);
	name = name.trim()
	pass = pass.trim()
	if(name && pass)
	{
		getSQL = "select * from account where username=? limit 1";
		getParam = [name];
		
		con.connect();
		con.query(getSQL, getParam, function(err, result){
			if(err)
			{
				console.log(err.message);
				let msg = {
					'code' : '9999',
					'message' : '数据库连接失败'
				}
				res.status(200).end(JSON.stringify(msg));
				console.log("user [%s] login failed with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
				return;
			}			
			if(result)
			{			
				let uid = result[0].id,
					upass = result[0].password;
				if(upass != pass)
				{
					let msg = {
						code : '1002',
						'message' : '密码错误'
					}
					res.status(200).end(JSON.stringify(msg));
					console.log("user [%s] login failed with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
					return;
				}
				let time = Date.now(),
					msg = {
						'code' : '1000',
						'message' : '成功',
						'mesage' : '登陆成功',
						'event' : 'login',
						'timestamp' : time,
						'sign' : getMD5(time + 'login' + uid),
						'userid' : uid,
					}
				console.log("user [%s] login successful with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
				res.status(200).end(JSON.stringify(msg));
			}		
	});
	}else{
		let msg = {
			code : '8888',
			'message' : '未知错误'
		}
		res.status(200).end(JSON.stringify(msg));
	}
});

/***
*用户注册
*/
app.post('/reg.php', function(req, res){
	//res.header("Content-Type", "text/html;charset=utf-8");
	let name = req.body.loginName,
		pass = req.body.loginPwd,
		con = mysql.createConnection(config.SQLAcc);
	name = name.trim()
	pass = pass.trim()
	if(name && pass)
	{
		let getSQL = "select * from account where username=? limit 1",
			getParam = [name],
			upSQL = "insert into account(username,password) values(?,?)",
			upParam = [name, pass];
		con.connect();
		con.query(getSQL, getParam, function(err, result){
			if(err)
			{
				console.log(err.message);
				let msg = {
					'code' : '9999',
					'message' : '数据库连接失败'
				}
				res.status(200).end(JSON.stringify(msg));
				console.log("user [%s] reg failed with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
				return;
			}
			if(result)
			{
				if(result.length == 0 || result == null)
				{
					con.query(upSQL, upParam, function(err, result){
						if(err)
						{
							console.log(err.message);
							let msg = {
								'code' : '9999',
								'message' : '数据库连接失败'
							}
							res.status(200).end(JSON.stringify(msg));
							console.log("In Reg up1 : %s", err.message);
							return;
						}
						if(result)
						{
							if(result.affectedRows > 0)
							{
								con.query(getSQL, getParam, function(err, result){
									if(err)
									{
										console.log(err.message);
										let msg = {
											'code' : '9999',
											'message' : '数据库连接失败'
										}
										res.status(200).end(JSON.stringify(msg));
										console.log("In Reg get2 : %s", err.message);
										return;
									}
									if(result)
									{
										let uid = result[0].id,
											time = Date.now(),
											msg = {
												'code':'1000',
												'message':'成功',
												'mesage':'注册成功',
												'event':'register',
												'timestamp':time,
												'sign':getMD5(time + 'register'+ uid),
												'userid':uid,
											}
										res.status(200).end(JSON.stringify(msg));
										console.log("user [%s] reg successful with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
										return;
									}
									
									con.end()
								});
							}else{
								let msg = {
									'code' : '9999',
									'message' : '账号注册失败',
								}
								res.status(200).end(JSON.stringify(msg));
								console.log("user [%s] reg failed with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
								return;
							}
						}
					});
				}else{
					let msg = {
						'code' : '1006',
						'message' : '账号已存在',
						}
					res.status(200).end(JSON.stringify(msg));
					console.log("user [%s] reg failed with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
					return;
				}
			}
		});
	}else{
		let msg = {
			code : '8888',
			'message' : '未知错误'
		}
		console.log("user [%s] reg failed with message: %s at %s", name, msg['message'], moment().format('YYYY-MM-DD HH:mm:ss'));
		res.status(200).end(JSON.stringify(msg));		
	}
});

/***
*获取物品列表
*/
app.get('/getlist', function(req, res){
	var fRead = fs.createReadStream('./item.txt');
    var objReadline = readline.createInterface({
        input:fRead
    });
    var arr = new Array();
    objReadline.on('line',function (line) {
        let tt = line.split(';');
		let ss = '<option id="' + tt[2] + '" class="optionss" value="' + tt[0] + '">' + tt[1] + '</option>';
		arr.push(ss);
    });
    objReadline.on('close',function () {
        //操作
		res.header("Content-Type", "application/json; charset=utf-8");
		res.status(200).end(JSON.stringify(arr));
    });
});


/***
*gm获取登录页面
*/
app.get('/gm/login', function(req, res){
	res.sendFile(rootPath + '/login.html');
});

/***
*gm登录
*/
app.post('/gm/login', function(req, res){
	if(req.body.user == config.admin.acc && req.body.pass == config.admin.pass)
	{
		req.session.isLogin = 'isaroot';
		res.redirect('/gm/home');
	}else{
		res.header("Content-Type", "text/html;charset=utf-8");
		res.status(200).end("<script>alert('账号或密码错误！');window.location.href='/gm/login';</script>");
	}
});

/***
*gm注销登录
*/
app.post('/gm/logout', function(req, res){
	req.session.isLogin = null;
	res.header("Content-Type", "text/html;charset=utf-8");
	res.status(200).end("<script>alert('注销成功！');window.location.href='/gm/login';</script>");
});

/***
*获取GM操作页
*/
app.get('/gm/home', function(req, res){
	if(req.session.isLogin != 'isaroot')
	{
		res.header("Content-Type", "text/html;charset=utf-8");
		res.status(200).end("<script>alert('未登录！');window.location.href='/gm/login';</script>");
	}
	res.sendFile(rootPath + '/home.html');
});

/***
*gm后台操作
*/
app.post('/gm/api', function(req, res){
	res.header("Content-Type", "text/html;charset=utf-8");
	
	if(req.session.isLogin != 'isaroot')
	{
		res.status(200).end("<script>alert('未登录！');window.location.href='/gm/login';</script>");
		return;
	}
	var args = req.body;
	var optType = args.sub;
	var uid, num, username, item;		
	
	if(args.uid != undefined)
	{	
		uid = args.uid;
		uid = uid.replace('-', '');
		if(uid == '' || uid.length != 16)
		{
			res.status(200).end("<script>alert('请输入正确的角色ID！');history.go(-1);</script>");
			return;
		}
	}
	if(args.num != undefined)
	{
		num = args.num.trim();
		if(num == '')
		{
			res.status(200).end("<script>alert('请输入物品或元宝数！');history.go(-1);</script>");
			return;
		}
		if(num < 1 || num > 9999999)
		{
			res.status(200).end("<script>alert('金币或元宝上限：7个9！');history.go(-1);</script>");
			return;
		}
	}
	if(args.username != undefined)
	{
		username = args.username.trim();
		if(username == '')
		{
			res.status(200).end("<script>alert('请输入角色昵称！');history.go(-1);</script>");
			return;
		}
	}
	if(args.item != undefined)
	{
		item = args.item.trim();
	}
	
	/***
	*具体操作
	*/
	if(optType == 'pay')
	{
		var	conCh = mysql.createConnection(config.SQLCharge);
		conCh.connect();
		
		let getSQL = "select * from charge where roleid = ?";
			getParam = [uid];
		conCh.query(getSQL, getParam, function(err, result){
			if(err)
			{
				res.status(200).end("<script>alert('数据库连接失败！');history.go(-1);</script>");
				conCh.end();
				//conTLBB.end();
				return;
			}
			if(result)
			{
				if(result[0].id)
				{
					let upSQL = "update charge set num = num + ? where roleid = ?",
						upParam = [num, uid];
					conCh.query(upSQL, upParam, function(err, result){
						if(result.affectedRows > 0)
						{
							res.status(200).end("<script>alert('元宝充值成功,请重登录游戏或到商城充值手动收账！');history.go(-1);</script>");
							conCh.end();
							//conTLBB.end();
						}
					});
				}
				else
				{
					let intSQL = "insert into charge (roleid, num) values(?, ?)",
						intParam = [uid, num];
						conCh.query(intSQL, intParam, function(err, result){
							if(result.affectedRows > 0)
							{
								res.status(200).end("<script>alert('元宝充值成功,请重登录游戏或到商城充值手动收账！');history.go(-1);</script>");
								conCh.end();
								//conTLBB.end();
							}
						});
				}
			}
		});
	}else if(optType == 'mail')
	{
		var	conTLBB = mysql.createConnection(config.SQLTLBB);
		conTLBB.connect();
		
		let mem = new memcache("127.0.0.1:11211");
		mem.del('0x'+uid, function(err){
			if(err)
			{
				res.status(200).end("<script>alert('角色重新上下线后发送！');history.go(-1);</script>");
				mem.end();
				conTLBB.end();
				return;
			}
			let getSQL = 'select * from t_char where charname = ?',
				getParam = [username];
			conTLBB.query(getSQL, getParam, function(err, result){
				if(err)
				{
					res.status(200).end("<script>alert('数据库连接失败！');history.go(-1);</script>");
					//conCh.end();
					conTLBB.end();
					return;
				}
				if(result)
				{				
					//console.log(result);
					if(result.length > 0)
					{
						var uguid = BigInt(result[0].charguid);
						let getSQL = 'SELECT * FROM t_usermail order by aid DESC limit 1';
						conTLBB.query(getSQL, function(err, result){
							if(result)
							{
								var id,
									timestamp = new Date().getTime();
								if(result[0].aid)
								{
									let tmp = BigInt(result[0].guid);
									id = tmp + BigInt(1);
								}									
								else
									id = BigInt(5601355335076910000);
								let intSQL = "insert into t_usermail (guid,sendguid,sendname,writetime,receiveguid,readtime,mailtype,content,moneytype,moneyvalue,boxtype,isvalid,itemguid,dataid,binded,stackcount,createtime,enchancelevel,enchanceexp,enchancetotalexp,starlevel,startimes,dynamicdata1,dynamicdata2,dynamicdata3,dynamicdata4,dynamicdata5,dynamicdata6,dynamicdata7,dynamicdata8,origin) values(?,'-1','System',?,?,'0','1','请注意查收!','-1','0','2','1',?,?,'1',?,?,'0','0','0','0','0','0','0','0','0','0','0','0','0','40020')",
									intParam = [id, timestamp, uguid, id, item, num, new Date().getTime()];
								conTLBB.query(intSQL, intParam, function(err, result){
									if(err)
									{
										console.log(5);
										console.log(err);
									}
									if(result)
									{										
										if(result.affectedRows > 0)
										{
											let mem = new memcache("127.0.0.1:11211");
											mem.del('0x' + uid, function(err){
												res.status(200).end("<script>alert('邮件发送成功！');history.go(-1);</script>");
												//conCh.end();
												conTLBB.end();
												mem.end();
												return;
											});
										}else{
											res.status(200).end("<script>alert('邮件发送失败！');history.go(-1);</script>");
												//conCh.end();
												conTLBB.end();
												return;
										}
									}									
								})
							}
						});
					}else{
						res.status(200).end("<script>alert('未找到角色！');history.go(-1);</script>");
						//conCh.end();
						conTLBB.end();
						return;
					}
				}
			});
		});
	}else if(optType == 'jb')
	{
		var	conTLBB = mysql.createConnection(config.SQLTLBB);
		conTLBB.connect();
				
		let mem = new memcache("127.0.0.1:11211");
		mem.del('0x'+uid, function(err){
			if(err)
			{
				res.status(200).end("<script>alert('角色重新上下线后发送！');history.go(-1);</script>");
				mem.end();
				conTLBB.end();
				return;
			}
			let getSQL = 'select * from t_char where charname = ?',
				getParam = [username];
			conTLBB.query(getSQL, getParam, function(err, result){
				if(err)
				{
					res.status(200).end("<script>alert('数据库连接失败！');history.go(-1);</script>");
					//conCh.end();
					conTLBB.end();
					return;
				}
				if(result)
				{					
					if(result.length > 0)
					{
						let upSQL = "update t_char set moneycoin = moneycoin + ? where charname = ?",
							upParam = [num, username];
						conTLBB.query(upSQL, upParam, function(err, result){
							if(result)
							{
								if(result.affectedRows > 0)
								{
									let mem = new memcache("127.0.0.1:11211");
									mem.del('0x'+uid, function(err){				
										res.status(200).end("<script>alert('金币充值成功！');history.go(-1);</script>");
										mem.end();
										conTLBB.end();
										return;
									});									
								}
								else{
									res.status(200).end("<script>alert('金币充值失败！');history.go(-1);</script>");
									conTLBB.end();
									return;								
								}	
							}													
						});
					}else{
						res.status(200).end("<script>alert('未找到角色！');history.go(-1);</script>");
						//conCh.end();
						conTLBB.end();
						return;
					}
				}
			});
		});
	}else if(optType == 'by')
	{
		var	conTLBB = mysql.createConnection(config.SQLTLBB);
		conTLBB.connect();
				
		let mem = new memcache("127.0.0.1:11211");
		mem.del('0x'+uid, function(err){
			if(err)
			{
				res.status(200).end("<script>alert('角色重新上下线后发送！');history.go(-1);</script>");
				mem.end();
				conTLBB.end();
				return;
			}
			let getSQL = 'select * from t_char where charname = ?',
				getParam = [username];
			conTLBB.query(getSQL, getParam, function(err, result){
				if(err)
				{
					res.status(200).end("<script>alert('数据库连接失败！');history.go(-1);</script>");
					//conCh.end();
					conTLBB.end();
					return;
				}
				if(result)
				{					
					if(result.length > 0)
					{
						let upSQL = "update t_char set moneyybbind = moneyybbind + ? where charname = ?",
							upParam = [num, username];
						conTLBB.query(upSQL, upParam, function(err, result){
							if(result)
							{
								if(result.affectedRows > 0)
								{
									let mem = new memcache("127.0.0.1:11211");
									mem.del('0x'+uid, function(err){				
										res.status(200).end("<script>alert('绑元充值成功！');history.go(-1);</script>");
										mem.end();
										conTLBB.end();
										return;
									});									
								}
								else{
									res.status(200).end("<script>alert('绑元充值失败！');history.go(-1);</script>");
									conTLBB.end();
									return;								
								}		
							}												
						});
					}else{
						res.status(200).end("<script>alert('未找到角色！');history.go(-1);</script>");
						//conCh.end();
						conTLBB.end();
						return;
					}
				}
			});
		});
	}
});

app.get('/bi.php', function(req, res){
	res.status(200).redirect('/')
});

function getMD5(data)
{
	let hash = crypto.createHash('md5');
	return hash.update(data).digest('base64');
}

//开启监听
try{
	let port = config.Port;
	app.listen(port, function(){
	console.log("\n\n--------------------------------------------------------");
	console.log('Server start at Port : %s, time : %s', port, moment().format('YYYY-MM-DD HH:mm:ss'));
});
}catch(ex){
	console.log(ex.message);
}