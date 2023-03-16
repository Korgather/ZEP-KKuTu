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

const MainDB = require("../db");
const JLog = require("../../sub/jjlog");
// const Ajae	 = require("../../sub/ajaejs").checkAjae;
const passport = require("passport");
const glob = require("glob-promise");
const GLOBAL = require("../../sub/global.json");
const config = require("../../sub/auth.json");
const path = require("path");
var Const = require("../../const");
const CustomStrategy = require("passport-custom").Strategy;

function process(req, accessToken, MainDB, $p, done) {
	$p.token = accessToken;
	$p.sid = req.session.id;

	let now = Date.now();
	$p.sid = req.session.id;
	req.session.admin = GLOBAL.ADMIN.includes($p.id);
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

	done(null, $p);
}

exports.run = (Server, page) => {
	//passport configure
	passport.serializeUser((user, done) => {
		JLog.log("serializeUser");
		JLog.log(user.id);
		done(null, user);
	});

	passport.deserializeUser((obj, done) => {
		JLog.log("deserializeUser");
		done(null, obj);
	});

	const strategyList = {};

	for (let i in config) {
		try {
			let auth = require(path.resolve(__dirname, "..", "auth", "auth_" + i + ".js"));
			Server.get("/login/" + auth.config.vendor, passport.authenticate(auth.config.vendor));
			Server.get(
				"/login/" + auth.config.vendor + "/callback",
				passport.authenticate(auth.config.vendor, {
					successRedirect: "/",
					failureRedirect: "/loginfail",
				})
			);
			passport.use(new auth.config.strategy(auth.strategyConfig, auth.strategy(process, MainDB)));
			strategyList[auth.config.vendor] = {
				vendor: auth.config.vendor,
				displayName: auth.config.displayName,
				color: auth.config.color,
				fontColor: auth.config.fontColor,
			};

			JLog.info(`OAuth Strategy ${i} loaded successfully.`);
		} catch (error) {
			JLog.error(`OAuth Strategy ${i} is not loaded`);
			JLog.error(error.message);
		}
	}

	// Passport 설정
	passport.use(
		"no-auth",
		new CustomStrategy((req, done) => {
			var zepID = req.query.id;

			if (zepID) {
				const $p = {};
				$p.authType = "zep";
				$p.id = zepID;
				$p.name = req.query.name;
				$p.title = req.query.name;
				$p.image = req.query.image;
				$p.sid = req.session.id;
				let now = Date.now();
				$p.sid = req.session.id;

				req.session.profile = $p;
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

				JLog.log(`저장된 세션아이디 ${req.session.id}`);

				// req.session.passport.user = $p;
				// req.session.save((err) => {});
				// const user = $p;
				// 인증 완료 처리
				done(null, $p);
			}
		})
	);

	function onAuthentication(req, res) {
		req.login(req.user, (err) => {
			if (err) {
				JLog.log(`login error: ${err}`);
				return res.redirect("/");
			}
			JLog.log(`login success`);

			req.session.save((err) => {
				if (err) {
					JLog.log(`session save error: ${err}`);
					return res.redirect("/");
				}
				res.redirect("/");
			});
		});
	}

	// 인증을 처리하는 라우터
	Server.get("/login/zep", passport.authenticate("no-auth", { session: true, failWithError: true }), onAuthentication, (err, req, res, next) => {
		// 인증에 실패했을 경우의 처리
		JLog.log(`Authentication error: ${err}`);
		res.redirect("/");
	});

	Server.get("/", function (req, res) {
		var server = req.query.server;
		JLog.log(`리다이렉트 후 세션 아이디 ${req.session.id}`);
		if (req.cookies && req.cookies["connect.sid"]) {
			JLog.log(req.cookies["connect.sid"]);
		} else {
			JLog.log("connect.sid 읽을 수 없음");
		}

		MainDB.session.findOne(["_id", req.session.id]).on(function ($ses) {
			if (global.isPublic) {
				onFinish($ses);
			} else {
				if ($ses) $ses.profile.sid = $ses._id;
				onFinish($ses);
			}
		});
		function onFinish($doc) {
			// zepID ||
			// zepID ||
			var id = req.session.id;

			if (!req.session.profile) {
				if ($doc) {
					req.session.profile = $doc.profile;
					id = $doc.profile.sid;
				} else {
					delete req.session.profile;
				}
			}

			page(req, res, Const.MAIN_PORTS[server] ? "kkutu" : "portal", {
				_page: "kkutu",
				_id: id,
				PORT: Const.MAIN_PORTS[server],
				HOST: req.hostname,
				PROTOCOL: Const.IS_SECURED ? "wss" : "ws",
				TEST: req.query.test,
				MOREMI_PART: Const.MOREMI_PART,
				AVAIL_EQUIP: Const.AVAIL_EQUIP,
				CATEGORIES: Const.CATEGORIES,
				GROUPS: Const.GROUPS,
				MODE: Const.GAME_TYPE,
				RULE: Const.RULE,
				OPTIONS: Const.OPTIONS,
				KO_INJEONG: Const.KO_INJEONG,
				EN_INJEONG: Const.EN_INJEONG,
				KO_THEME: Const.KO_THEME,
				EN_THEME: Const.EN_THEME,
				IJP_EXCEPT: Const.IJP_EXCEPT,
				ogImage: "http://kkutu.kr/img/kkutu/logo.png",
				ogURL: "https://zep-kkutu.online/",
				ogTitle: "ZEP 끄투서버",
				ogDescription: "ZEP에서 끝말잇기 한판?",
			});
		}
	});

	Server.get("/login", (req, res) => {
		if (global.isPublic) {
			page(req, res, "login", { _id: req.session.id, text: req.query.desc, loginList: strategyList });
		} else {
			let now = Date.now();
			let id = req.query.id || "ADMIN";
			let lp = {
				id: id,
				title: "LOCAL #" + id,
				birth: [4, 16, 0],
				_age: { min: 20, max: undefined },
			};
			MainDB.session
				.upsert(["_id", req.session.id])
				.set(["profile", JSON.stringify(lp)], ["createdAt", now])
				.on(function ($res) {
					MainDB.users.update(["_id", id]).set(["lastLogin", now]).on();
					req.session.admin = true;
					req.session.profile = lp;
					res.redirect("/");
				});
		}
	});

	Server.get("/logout", (req, res) => {
		if (!req.session.profile) {
			return res.redirect("/");
		} else {
			req.session.destroy();
			res.redirect("/");
		}
	});

	Server.get("/loginfail", (req, res) => {
		page(req, res, "loginfail");
	});
};
