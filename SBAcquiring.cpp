/*++

Program name:

  Apostol Web Service

Module Name:

  SBAcquiring.cpp

Notices:

  Module: Sberbank Acquiring

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "SBAcquiring.hpp"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CSBAcquiring ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CSBAcquiring::CSBAcquiring(CModuleProcess *AProcess) : CApostolModule(AProcess, "sba", "worker/sba") {
            m_Headers.Add("Authorization");

            CSBAcquiring::InitMethods();

            m_CheckDate = Now();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoProxy(Connection); }));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , std::bind(&CSBAcquiring::DoProxy, this, _1)));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , std::bind(&CSBAcquiring::DoOptions, this, _1)));
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(false, std::bind(&CSBAcquiring::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CSBAcquiring::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CSBAcquiring::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CSBAcquiring::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CSBAcquiring::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CSBAcquiring::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CSBAcquiring::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoVerbose(CSocketEvent *Sender, CTCPConnection *AConnection, LPCTSTR AFormat, va_list args) {
            Log()->Debug(0, AFormat, args);
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::DoProxyExecute(CTCPConnection *AConnection) {

            auto LProxyConnection = dynamic_cast<CHTTPClientConnection*> (AConnection);
            auto LProxy = dynamic_cast<CHTTPProxy*> (LProxyConnection->Client());

            auto LProxyRequest = LProxyConnection->Request();
            auto LProxyReply = LProxyConnection->Reply();

            DebugReply(LProxyReply);

            auto LConnection = LProxy->Connection();

            auto LRequest = LConnection->Request();
            auto LReply = LConnection->Reply();

            if (LConnection->Connected()) {

                CStringList LRouts;
                SplitColumns(LProxyRequest->Location.pathname, LRouts, '/');

                if (LRouts.Count() >= 3) {

                    const auto& LAction = LRouts[2];

                    const auto& reply = CJSON(LProxyReply->Content);
                    const auto& errorCode = reply.HasOwnProperty("errorCode") ? reply["errorCode"].AsInteger() : 0;

                    if (errorCode == 0) {

                        const auto& Token = LConnection->Data()["Token"];
                        const auto& Agent = LProxyRequest->UserAgent;

                        if (LAction == "registerPreAuth.do") {

                            const auto& orderNumber = LRequest->FormData.Values("orderNumber");
                            const auto& clientId = LRequest->FormData.Values("clientId");

                            const auto& orderId = reply["orderId"];

                            CJSON Payload;

                            Payload.Object().AddPair("id", 0);
                            Payload.Object().AddPair("code", orderNumber);
                            if (!clientId.IsEmpty())
                                Payload.Object().AddPair("client", clientId);
                            Payload.Object().AddPair("uuid", orderId);

                            AuthorizedFetch(LConnection, Token, "POST", "/api/v1/order/set", Payload, Agent);

                        } else if (LAction == "getBindings.do") {

                            const auto& clientId = LRequest->FormData.Values("clientId");
                            const auto& bindings = reply["bindings"];

                            CJSONValue Data;

                            Data.Object().AddPair("type", "json");
                            Data.Object().AddPair("code", "bindings");
                            Data.Object().AddPair("data", bindings);

                            CJSONArray DataArray;

                            DataArray.Add(Data);

                            CJSON Payload;

                            Payload.Object().AddPair("id", clientId);
                            Payload.Object().AddPair("data", DataArray);

                            AuthorizedFetch(LConnection, Token, "POST", "/api/v1/object/data/set", Payload, Agent);
                        }
                    }
                }

                LConnection->CloseConnection(true);

                LReply->ContentType = CHTTPReply::json;
                LReply->Content = LProxyReply->Content;

                LConnection->SendReply(LProxyReply->Status, nullptr, true);
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            auto LProxyConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
            auto LProxy = dynamic_cast<CHTTPProxy *> (LProxyConnection->Client());

            Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", LProxy->Host().c_str(), LProxy->Port(), E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoEventHandlerException(CPollEventHandler *AHandler, const Delphi::Exception::Exception &E) {
            auto LProxyConnection = dynamic_cast<CHTTPClientConnection *> (AHandler->Binding());
            DoProxyException(LProxyConnection, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyConnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (Assigned(LConnection)) {
                if (!LConnection->ClosedGracefully()) {
                    auto socket = LConnection->Socket();
                    if (Assigned(socket)) {
                        Log()->Message(_T("[%s:%d] Proxy connected."), socket->Binding()->PeerIP(), socket->Binding()->PeerPort());
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyDisconnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (Assigned(LConnection)) {
                if (!LConnection->ClosedGracefully()) {
                    auto socket = LConnection->Socket();
                    if (Assigned(socket)) {
                        Log()->Message(_T("[%s:%d] Proxy disconnected."), socket->Binding()->PeerIP(), socket->Binding()->PeerPort());
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        CHTTPProxy *CSBAcquiring::GetProxy(CHTTPServerConnection *AConnection) {
            auto LProxy = m_ProxyManager.Add(AConnection);
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            LProxy->OnVerbose([this](auto && Sender, auto && AConnection, auto && AFormat, auto && args) { DoVerbose(Sender, AConnection, AFormat, args); });

            LProxy->OnExecute([this](auto && AConnection) { return DoProxyExecute(AConnection); });

            LProxy->OnException([this](auto && AConnection, auto && AException) { DoProxyException(AConnection, AException); });
            LProxy->OnEventHandlerException([this](auto && AHandler, auto && AException) { DoEventHandlerException(AHandler, AException); });

            LProxy->OnConnected([this](auto && Sender) { DoProxyConnected(Sender); });
            LProxy->OnDisconnected([this](auto && Sender) { DoProxyDisconnected(Sender); });
#else
            LProxy->OnVerbose(std::bind(&CSBAcquiring::DoVerbose, this, _1, _2, _3, _4));

            LProxy->OnExecute(std::bind(&CSBAcquiring::DoProxyExecute, this, _1));

            LProxy->OnException(std::bind(&CSBAcquiring::DoProxyException, this, _1, _2));
            LProxy->OnEventHandlerException(std::bind(&CSBAcquiring::DoEventHandlerException, this, _1, _2));

            LProxy->OnConnected(std::bind(&CSBAcquiring::DoProxyConnected, this, _1));
            LProxy->OnDisconnected(std::bind(&CSBAcquiring::DoProxyDisconnected, this, _1));
#endif
            return LProxy;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::AuthorizedFetch(CHTTPServerConnection *AConnection, const CString &Token, const CString &Method,
                const CString &Path, const CJSON &Payload, const CString &Agent) {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQResult *Result;

                try {
                    for (int I = 0; I < APollQuery->Count(); I++) {
                        Result = APollQuery->Results(I);

                        if (Result->ExecStatus() != PGRES_TUPLES_OK)
                            throw Delphi::Exception::EDBError(Result->GetErrorMessage());
                    }
                } catch (std::exception &e) {
                    m_CheckDate = Now() + (CDateTime) 60 / SecsPerDay;
                    Log()->Error(APP_LOG_EMERG, 0, e.what());
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                m_CheckDate = Now() + (CDateTime) 60 / SecsPerDay;
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            };

            const auto& Host = GetHost(AConnection);

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.fetch(%s, '%s', '%s', '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Token).c_str(),
                                     Method.c_str(),
                                     Path.c_str(),
                                     Payload.ToString().c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str()
            ));

            try {
                ExecSQL(SQL, AConnection, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                m_CheckDate = Now() + (CDateTime) 10 / SecsPerDay;
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::VerifyToken(const CString &Token) {

            auto decoded = jwt::decode(Token);

            const auto& aud = CString(decoded.get_audience());
            const auto& alg = CString(decoded.get_algorithm());
            const auto& iss = CString(decoded.get_issuer());

            const auto& Providers = Server().Providers();

            CString Application;
            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& Provider = Providers[Index].Value();
            const auto& Secret = OAuth2::Helper::GetSecret(Provider, Application);

            CStringList Issuers;
            Provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::token_verification_exception("Token doesn't contain the required issuer.");

            if (alg == "HS256") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs256{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS384") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs384{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS512") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs512{Secret});
                verifier.verify(decoded);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization) {

            const auto &LHeaders = ARequest->Headers;
            const auto &LCookies = ARequest->Cookies;

            const auto &LAuthorization = LHeaders.Values(_T("Authorization"));

            if (LAuthorization.IsEmpty()) {

                const auto &headerSession = LHeaders.Values(_T("Session"));
                const auto &headerSecret = LHeaders.Values(_T("Secret"));

                Authorization.Username = headerSession;
                Authorization.Password = headerSecret;

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << LAuthorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization) {

            auto LRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(LRequest, Authorization)) {
                    if (Authorization.Schema == CAuthorization::asBearer) {
                        VerifyToken(Authorization.Token);
                        return true;
                    }
                }

                if (Authorization.Schema == CAuthorization::asBasic)
                    AConnection->Data().Values("Authorization", "Basic");

                ReplyError(AConnection, CHTTPReply::unauthorized, "Unauthorized.");
            } catch (jwt::token_expired_exception &e) {
                ReplyError(AConnection, CHTTPReply::forbidden, e.what());
            } catch (jwt::token_verification_exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxy(CHTTPServerConnection *AConnection) {

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CHTTPReply::json;

            auto LProxy = GetProxy(AConnection);
            auto LProxyRequest = LProxy->Request();

            const auto& LProfile = LRequest->Params["profile"];
            const auto& profile = LProfile.IsEmpty() ? "main" : LProfile;

            const auto& uri = m_Profiles[profile]["uri"];
            const auto& userName = m_Profiles[profile]["username"];
            const auto& password = m_Profiles[profile]["password"];

            CStringList LRouts;
            SplitColumns(LRequest->Location.pathname, LRouts, '/');

            if (LRouts.Count() < 2) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            if (uri.IsEmpty()) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            CString LPath;
            for (int I = 1; I < LRouts.Count(); ++I) {
                LPath.Append('/');
                LPath.Append(LRouts[I]);
            }

            CAuthorization LAuthorization;
            if (!CheckAuthorization(AConnection, LAuthorization))
                return;

            AConnection->Data().Values("Token", LAuthorization.Token);

            CLocation Location(uri + LPath);

            LProxy->Host() = Location.hostname;
            LProxy->Port(Location.port);
            LProxy->UsedSSL(Location.port == 443);

            const auto& LContentType = LRequest->Headers.Values("Content-Type");
            const auto& LUserAgent = LRequest->Headers.Values("User-Agent");

            LProxyRequest->Clear();

            LProxyRequest->Location = Location;
            LProxyRequest->UserAgent = LUserAgent;

            LProxyRequest->Content = LRequest->Content;

            if (!LProxyRequest->Content.IsEmpty())
                LProxyRequest->Content << _T("&");

            LProxyRequest->Content << _T("userName=");
            LProxyRequest->Content << CHTTPServer::URLEncode(userName);

            LProxyRequest->Content << _T("&password=");
            LProxyRequest->Content << CHTTPServer::URLEncode(password);

            LProxyRequest->CloseConnection = true;

            AConnection->CloseConnection(false);

            CHTTPRequest::Prepare(LProxyRequest, LRequest->Method.c_str(), Location.pathname.c_str(), LContentType.c_str());

            DebugRequest(LProxyRequest);

            LProxy->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config) {
            Config.AddPair("uri", IniFile.ReadString(Profile, "uri", Profile == "test" ? "https://3dsec.sberbank.ru" : "https://securepayments.sberbank.ru"));
            Config.AddPair("username", IniFile.ReadString(Profile, "username", ""));
            Config.AddPair("password", IniFile.ReadString(Profile, "password", ""));
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::Initialization(CModuleProcess *AProcess) {
            CApostolModule::Initialization(AProcess);
            LoadConfig(Config()->IniFile().ReadString(SectionName().c_str(), "config", "conf/sba.conf"), m_Profiles, InitConfig);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::Heartbeat() {
            CApostolModule::Heartbeat();
            m_ProxyManager.CleanUp();
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool(SectionName().c_str(), "enable", false) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::CheckLocation(const CLocation &Location) {
            return Location.pathname.SubString(0, 5) == _T("/sba/") || Location.pathname.SubString(0, 10) == _T("/sberbank/");
        }
    }
}
}