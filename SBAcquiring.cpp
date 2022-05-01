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

            auto pProxyConnection = dynamic_cast<CHTTPClientConnection*> (AConnection);
            auto pProxy = dynamic_cast<CHTTPProxy*> (pProxyConnection->Client());

            auto pProxyRequest = pProxyConnection->Request();
            auto pProxyReply = pProxyConnection->Reply();

            DebugReply(pProxyReply);

            auto pConnection = pProxy->Connection();

            auto pRequest = pConnection->Request();
            auto pReply = pConnection->Reply();

            if (pConnection->Connected()) {

                CStringList Routs;
                SplitColumns(pProxyRequest->Location.pathname, Routs, '/');

                if (Routs.Count() >= 3) {

                    const auto& action = Routs[2];

                    const auto& reply = CJSON(pProxyReply->Content);
                    const auto& errorCode = reply.HasOwnProperty("errorCode") ? reply["errorCode"].AsInteger() : 0;

                    if (errorCode == 0) {

                        const auto& Token = pConnection->Data()["Token"];
                        const auto& Agent = pProxyRequest->UserAgent;

                        if (action == "registerPreAuth.do") {

                            const auto& orderNumber = pRequest->FormData.Values("orderNumber");
                            const auto& clientId = pRequest->FormData.Values("clientId");

                            const auto& orderId = reply["orderId"];

                            CJSON Payload;

                            Payload.Object().AddPair("id", 0);
                            Payload.Object().AddPair("code", orderNumber);
                            if (!clientId.IsEmpty())
                                Payload.Object().AddPair("client", clientId);
                            Payload.Object().AddPair("uuid", orderId);

                            AuthorizedFetch(pConnection, Token, "POST", "/api/v1/order/set", Payload, Agent);

                        } else if (action == "getBindings.do") {

                            const auto& clientId = pRequest->FormData.Values("clientId");
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

                            AuthorizedFetch(pConnection, Token, "POST", "/api/v1/object/data/set", Payload, Agent);
                        }
                    }
                }

                pConnection->CloseConnection(true);

                pReply->ContentType = CHTTPReply::json;
                pReply->Content = pProxyReply->Content;

                pConnection->SendReply(pProxyReply->Status, nullptr, true);
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E) {
            auto pProxyConnection = dynamic_cast<CHTTPClientConnection *> (AConnection);
            auto pProxy = dynamic_cast<CHTTPProxy *> (pProxyConnection->Client());

            Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", pProxy->Host().c_str(), pProxy->Port(), E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoEventHandlerException(CPollEventHandler *AHandler, const Delphi::Exception::Exception &E) {
            auto pProxyConnection = dynamic_cast<CHTTPClientConnection *> (AHandler->Binding());
            DoProxyException(pProxyConnection, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyConnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (Assigned(pConnection)) {
                if (!pConnection->ClosedGracefully()) {
                    auto socket = pConnection->Socket();
                    if (Assigned(socket)) {
                        Log()->Message(_T("[%s:%d] Proxy connected."), socket->Binding()->PeerIP(), socket->Binding()->PeerPort());
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (Assigned(pConnection)) {
                if (!pConnection->ClosedGracefully()) {
                    auto socket = pConnection->Socket();
                    if (Assigned(socket)) {
                        Log()->Message(_T("[%s:%d] Proxy disconnected."), socket->Binding()->PeerIP(), socket->Binding()->PeerPort());
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        CHTTPProxy *CSBAcquiring::GetProxy(CHTTPServerConnection *AConnection) {
            auto pProxy = m_ProxyManager.Add(AConnection);
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            pProxy->OnVerbose([this](auto && Sender, auto && AConnection, auto && AFormat, auto && args) { DoVerbose(Sender, AConnection, AFormat, args); });

            pProxy->OnExecute([this](auto && AConnection) { return DoProxyExecute(AConnection); });

            pProxy->OnException([this](auto && AConnection, auto && AException) { DoProxyException(AConnection, AException); });
            pProxy->OnEventHandlerException([this](auto && AHandler, auto && AException) { DoEventHandlerException(AHandler, AException); });

            pProxy->OnConnected([this](auto && Sender) { DoProxyConnected(Sender); });
            pProxy->OnDisconnected([this](auto && Sender) { DoProxyDisconnected(Sender); });
#else
            pProxy->OnVerbose(std::bind(&CSBAcquiring::DoVerbose, this, _1, _2, _3, _4));

            pProxy->OnExecute(std::bind(&CSBAcquiring::DoProxyExecute, this, _1));

            pProxy->OnException(std::bind(&CSBAcquiring::DoProxyException, this, _1, _2));
            pProxy->OnEventHandlerException(std::bind(&CSBAcquiring::DoEventHandlerException, this, _1, _2));

            pProxy->OnConnected(std::bind(&CSBAcquiring::DoProxyConnected, this, _1));
            pProxy->OnDisconnected(std::bind(&CSBAcquiring::DoProxyDisconnected, this, _1));
#endif
            return pProxy;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::AuthorizedFetch(CHTTPServerConnection *AConnection, const CString &Token, const CString &Method,
                const CString &Path, const CJSON &Payload, const CString &Agent) {

            auto OnExecuted = [](CPQPollQuery *APollQuery) {

                CPQResult *pResult;

                try {
                    for (int I = 0; I < APollQuery->Count(); I++) {
                        pResult = APollQuery->Results(I);

                        if (pResult->ExecStatus() != PGRES_TUPLES_OK)
                            throw Delphi::Exception::EDBError(pResult->GetErrorMessage());
                    }
                } catch (std::exception &e) {
                    Log()->Error(APP_LOG_EMERG, 0, e.what());
                }
            };

            auto OnException = [](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                Log()->Error(APP_LOG_EMERG, 0, E.what());
            };

            const auto& host = GetRealIP(AConnection);

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.fetch(%s, '%s', '%s', '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Token).c_str(),
                                     Method.c_str(),
                                     Path.c_str(),
                                     Payload.ToString().c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(host).c_str()
            ));

            try {
                ExecSQL(SQL, AConnection, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
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

            const auto &headers = ARequest->Headers;
            const auto &cookies = ARequest->Cookies;

            const auto &authorization = headers.Values(_T("Authorization"));

            if (authorization.IsEmpty()) {

                const auto &headerSession = headers.Values(_T("Session"));
                const auto &headerSecret = headers.Values(_T("Secret"));

                Authorization.Username = headerSession;
                Authorization.Password = headerSecret;

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << authorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization) {

            auto pRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(pRequest, Authorization)) {
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

            auto pRequest = AConnection->Request();
            auto pReply = AConnection->Reply();

            pReply->ContentType = CHTTPReply::json;

            auto pProxy = GetProxy(AConnection);
            auto pProxyRequest = pProxy->Request();

            const auto& _profile = pRequest->Params["profile"];
            const auto& profile = _profile.IsEmpty() ? "main" : _profile;

            const auto& uri = m_Profiles[profile]["uri"];
            const auto& userName = m_Profiles[profile]["username"];
            const auto& password = m_Profiles[profile]["password"];

            CStringList Routs;
            SplitColumns(pRequest->Location.pathname, Routs, '/');

            if (Routs.Count() < 2) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            }

            if (uri.IsEmpty()) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            CString Path;
            for (int I = 1; I < Routs.Count(); ++I) {
                Path.Append('/');
                Path.Append(Routs[I]);
            }

            CAuthorization Authorization;
            if (!CheckAuthorization(AConnection, Authorization))
                return;

            AConnection->Data().Values("Token", Authorization.Token);

            CLocation Location(uri + Path);

            pProxy->Host() = Location.hostname;
            pProxy->Port(Location.port);
            pProxy->UsedSSL(Location.port == 443);

            const auto& content_type = pRequest->Headers.Values("Content-Type");
            const auto& user_agent = pRequest->Headers.Values("User-Agent");

            pProxyRequest->Clear();

            pProxyRequest->Location = Location;
            pProxyRequest->UserAgent = user_agent;

            pProxyRequest->Content = pRequest->Content;

            if (!pProxyRequest->Content.IsEmpty())
                pProxyRequest->Content << _T("&");

            pProxyRequest->Content << _T("userName=");
            pProxyRequest->Content << CHTTPServer::URLEncode(userName);

            pProxyRequest->Content << _T("&password=");
            pProxyRequest->Content << CHTTPServer::URLEncode(password);

            pProxyRequest->CloseConnection = true;

            AConnection->CloseConnection(false);

            CHTTPRequest::Prepare(pProxyRequest, pRequest->Method.c_str(), Location.pathname.c_str(), content_type.c_str());

            DebugRequest(pProxyRequest);

            pProxy->Active(true);
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