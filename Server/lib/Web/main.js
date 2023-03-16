/**
 * Rule the words! KKuTu Online
 * Copyright (C) 2017 JJoriping(op@jjo.kr)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * 볕뉘 수정사항:
 * Login 을 Passport 로 수행하기 위한 수정
 */

var WS = require("ws");
var Express = require("express");
var Exession = require("express-session");
var Redission = require("connect-redis")(Exession);
var Redis = require("redis");
var Parser = require("body-parser");
var DDDoS = require("dddos");
var Server = Express();
var DB = require("./db");
//볕뉘 수정 구문삭제 (28)
var JLog = require("../sub/jjlog");
var WebInit = require("../sub/webinit");
var GLOBAL = require("../sub/global.json");
var Secure = require("../sub/secure");
//볕뉘 수정
var passport = require("passport");
//볕뉘 수정 끝
var Const = require("../const");
var https = require("https");
var fs = require("fs");
const cors = require("cors");
var MainDB = require("./db");

var Language = {
	ko_KR: require("./lang/ko_KR.json"),
	en_US: require("./lang/en_US.json"),
};
//볕뉘 수정
var ROUTES = ["major", "consume", "admin", "login"];
//볕뉘 수정 끝
var page = WebInit.page;
var gameServers = [];

WebInit.MOBILE_AVAILABLE = ["portal", "main", "kkutu"];

require("../sub/checkpub");

JLog.info("<< KKuTu Web >>");
Server.set("views", __dirname + "/views");
Server.set("view engine", "pug");
Server.use(Express.static(__dirname + "/public"));
Server.use(Parser.urlencoded({ extended: true }));
Server.use(
	Exession({
		/* use only for redis-installed
 
	 store: new Redission({
		 client: Redis.createClient(),
		 ttl: 3600 * 12
	 }),*/
		secret: "kkutu",
		resave: false,
		saveUninitialized: true,
		cookie: {
			maxAge: 1000 * 60 * 60 * 24,
			// sameSite: "none",
			// secure: true,
		},
	})
);

Server.use((req, res, next) => {
	// res.header("Access-Control-Allow-Origin", "*");
	// res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	// res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
	// res.setHeader("P3P", 'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"');
	// res.setHeader("X-Content-Type-Options", "nosniff");

	res.setHeader("X-Frame-Options", "ALLOW-FROM https://zep-kkutu.online https://zep.us");
	res.setHeader("Content-Security-Policy", "frame-ancestors https://zep-kkutu.online https://zep.us");

	//SameSite=None 및 Secure 속성 추가
	// if (req.secure) {
	// 	res.header("Set-Cookie", ["SameSite=None", "Secure"]);
	// }

	next();
});
//볕뉘 수정
Server.use(passport.initialize());
Server.use(passport.session());
// Server.use((req, res, next) => {
// 	if (req.session.passport) {
// 		delete req.session.passport;
// 	}
// 	next();
// });
Server.use((req, res, next) => {
	if (Const.IS_SECURED) {
		// if (req.protocol == "http") {
		// 	let url = "https://" + req.get("host") + req.path;
		// 	res.status(302).redirect(url);
		// } else {
		next();
		// }
	} else {
		next();
	}
});
//볕뉘 수정 끝
/* use this if you want
 
 DDDoS = new DDDoS({
	 maxWeight: 6,
	 checkInterval: 10000,
	 rules: [{
		 regexp: "^/(cf|dict|gwalli)",
		 maxWeight: 20,
		 errorData: "429 Too Many Requests"
	 }, {
		 regexp: ".*",
		 errorData: "429 Too Many Requests"
	 }]
 });
 DDDoS.rules[0].logFunction = DDDoS.rules[1].logFunction = function(ip, path){
	 JLog.warn(`DoS from IP ${ip} on ${path}`);
 };
 Server.use(DDDoS.express());*/

WebInit.init(Server, true);
DB.ready = function () {
	setInterval(function () {
		var q = ["createdAt", { $lte: Date.now() - 3600000 * 12 }];

		DB.session.remove(q).on();
	}, 600000);
	setInterval(function () {
		gameServers.forEach(function (v) {
			if (v.socket) v.socket.send(`{"type":"seek"}`);
			else v.seek = undefined;
		});
	}, 4000);
	JLog.success("DB is ready.");

	DB.kkutu_shop_desc.find().on(function ($docs) {
		var i, j;

		for (i in Language) flush(i);
		function flush(lang) {
			var db;

			Language[lang].SHOP = db = {};
			for (j in $docs) {
				db[$docs[j]._id] = [$docs[j][`name_${lang}`], $docs[j][`desc_${lang}`]];
			}
		}
	});
	Server.listen(3000);
	if (Const.IS_SECURED) {
		const options = Secure();
		https.createServer(options, Server).listen(443);
	}
};
Const.MAIN_PORTS.forEach(function (v, i) {
	var KEY = process.env["WS_KEY"];
	var protocol;
	if (Const.IS_SECURED) {
		protocol = "wss";
	} else {
		protocol = "ws";
	}
	gameServers[i] = new GameClient(KEY, `${protocol}://${GLOBAL.GAME_SERVER_HOST}:${v}/${KEY}`);
});
function GameClient(id, url) {
	var my = this;

	my.id = id;
	my.socket = new WS(url, { perMessageDeflate: false, rejectUnauthorized: false });

	my.send = function (type, data) {
		if (!data) data = {};
		data.type = type;

		my.socket.send(JSON.stringify(data));
	};
	my.socket.on("open", function () {
		JLog.info(`Game server #${my.id} connected`);
	});
	my.socket.on("error", function (err) {
		JLog.warn(`Game server #${my.id} has an error: ${err.toString()}`);
	});
	my.socket.on("close", function (code) {
		JLog.error(`Game server #${my.id} closed: ${code}`);
		my.socket.removeAllListeners();
		delete my.socket;
	});
	my.socket.on("message", function (data) {
		var _data = data;
		var i;

		data = JSON.parse(data);

		switch (data.type) {
			case "seek":
				my.seek = data.value;
				break;
			case "narrate-friend":
				for (i in data.list) {
					gameServers[i].send("narrate-friend", { id: data.id, s: data.s, stat: data.stat, list: data.list[i] });
				}
				break;
			default:
		}
	});
}
ROUTES.forEach(function (v) {
	require(`./routes/${v}`).run(Server, WebInit.page);
});

Server.use("/api/zep/users", cors({ origin: "https://zep.us" }));

Server.get("/api/zep/users", function (req, res) {
	// // 클라이언트의 IP 주소를 확인합니다.
	// const clientIP = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

	// // 클라이언트의 IP 주소를 기반으로 도메인 이름을 얻습니다.
	// const clientDomain = clientIP.split(":").pop();

	// // 허용되는 도메인이 아니면 403 Forbidden 오류를 반환합니다.
	// if (clientDomain !== "zep.us") {
	// 	return res.status(403).send("Access Denied");
	// }
	const $p = {};

	$p.authType = "discord";
	$p.id = "zep-" + req.query.id;
	$p.name = req.query.username;
	$p.title = req.query.username;
	$p.image = req.query.image;
	$p.sid = req.session.id;
	let now = Date.now();
	$p.sid = req.session.id;
	req.session.authType = $p.authType;
	MainDB.session
		.upsert(["_id", req.session.id])
		.set({
			profile: $p,
			createdAt: now,
		})
		.on();
	MainDB.users.findOne(["_id", $p.id]).on(($body) => {
		req.session.profile = $p;
		MainDB.users.update(["_id", $p.id]).set(["lastLogin", now]).on();
	});

	req.session.save(function () {
		res.redirect("/");
	});

	// var name = "my cookie name";
	// var value = "my cookie value";
	// document.cookie = encodeURIComponent(name) + "=" + encodeURIComponent(value);
	// console.log(document.cookie);
	// // document.cookie = "name=value; domain=부모페이지도메인";

	// res.status(200).send();
});

Server.get("/servers", function (req, res) {
	var list = [];

	gameServers.forEach(function (v, i) {
		list[i] = v.seek;
	});
	res.send({ list: list, max: Const.KKUTU_MAX });
});

//볕뉘 수정 구문 삭제(274~353)

Server.get("/legal/:page", function (req, res) {
	page(req, res, "legal/" + req.params.page);
});
