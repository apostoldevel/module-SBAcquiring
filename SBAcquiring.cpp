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

        CSBAcquiring::CSBAcquiring(CModuleProcess *AProcess) : CApostolModule(AProcess, "sba") {
            CSBAcquiring::InitMethods();
#ifdef _DEBUG
            m_HeartbeatInterval = (CDateTime) 15 / SecsPerDay; // 15 sec
#else
            m_HeartbeatInterval = (CDateTime) 30 / SecsPerDay; // 30 sec
#endif
            m_FixedDate = Now();
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

            auto LRequest = LProxyConnection->Request();
            auto LReply = LProxyConnection->Reply();

            DebugReply(LReply);

            auto LConnection = LProxy->Connection();

            if (LConnection->Connected()) {

                CStringList LRouts;
                SplitColumns(LRequest->Location.pathname, LRouts, '/');

                if (LRouts.Count() >= 3 && LRouts[2] == "getBindings.do") {
                    const auto& Json = CJSON(LReply->Content);
                    const auto& errorCode = Json["errorCode"].AsInteger();

                    if (errorCode == 0) {

                        const auto& Token = LConnection->Data()["Token"];
                        const auto& clientId = LConnection->Data()["clientId"];
                        const auto& Bindings = Json["bindings"];
                        const auto& Agent = LRequest->UserAgent;

                        CJSONValue Data;

                        Data.Object().AddPair("type", "json");
                        Data.Object().AddPair("code", "bindings");
                        Data.Object().AddPair("data", Bindings);

                        CJSONArray DataArray;

                        DataArray.Add(Data);

                        CJSON Payload;

                        Payload.Object().AddPair("id", clientId);
                        Payload.Object().AddPair("data", DataArray);

                        SetObjectData(LConnection, Token, Payload, Agent);
                    }
                }

                LConnection->CloseConnection(true);

                LConnection->Reply()->ContentType = CReply::json;
                LConnection->Reply()->Content = LReply->Content;

                LConnection->SendReply(LReply->Status, nullptr, true);
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyException(CTCPConnection *AConnection, Delphi::Exception::Exception *AException) {

            auto LProxyConnection = dynamic_cast<CHTTPClientConnection*> (AConnection);
            auto LProxy = dynamic_cast<CHTTPProxy*> (LProxyConnection->Client());

            auto LConnection = LProxy->Connection();

            auto LReply = LProxyConnection->Reply();

            DebugReply(LReply);

            LConnection->SendStockReply(CReply::internal_server_error, true);

            Log()->Error(APP_LOG_EMERG, 0, "[%s:%d] %s", LProxy->Host().c_str(), LProxy->Port(), AException->what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoEventHandlerException(CPollEventHandler *AHandler, Delphi::Exception::Exception *AException) {
            auto LConnection = dynamic_cast<CHTTPClientConnection*> (AHandler->Binding());
            auto LProxy = dynamic_cast<CHTTPProxy*> (LConnection->Client());

            if (Assigned(LProxy)) {
                auto LReply = LProxy->Connection()->Reply();
                ExceptionToJson(0, *AException, LReply->Content);
                LProxy->Connection()->SendReply(CReply::internal_server_error, nullptr, true);
            }

            Log()->Error(APP_LOG_EMERG, 0, AException->what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyConnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (LConnection != nullptr) {
                Log()->Message(_T("[%s:%d] Proxy connected."), LConnection->Socket()->Binding()->PeerIP(),
                               LConnection->Socket()->Binding()->PeerPort());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxyDisconnected(CObject *Sender) {
            auto LConnection = dynamic_cast<CHTTPClientConnection*> (Sender);
            if (LConnection != nullptr) {
                Log()->Message(_T("[%s:%d] Proxy disconnected."), LConnection->Socket()->Binding()->PeerIP(),
                               LConnection->Socket()->Binding()->PeerPort());
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

        void CSBAcquiring::SetObjectData(CHTTPServerConnection *AConnection, const CString &Token, const CJSON &Payload,
            const CString &Agent) {

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

            auto OnException = [this](CPQPollQuery *APollQuery, Delphi::Exception::Exception *AException) {
                m_CheckDate = Now() + (CDateTime) 60 / SecsPerDay;
                Log()->Error(APP_LOG_EMERG, 0, AException->what());
            };

            const auto& Host = GetHost(AConnection);

            CStringList SQL;

            SQL.Add(CString().Format("SELECT * FROM daemon.fetch(%s, '%s', '%s'::jsonb, %s, %s);",
                                     PQQuoteLiteral(Token).c_str(),
                                     "/object/data/set",
                                     Payload.ToString().c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str()
            ));

            ExecSQL(SQL, AConnection, OnExecuted, OnException);
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

            const CStringList& Issuers = Provider.GetIssuers(Application);
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

        bool CSBAcquiring::CheckAuthorizationData(CRequest *ARequest, CAuthorization &Authorization) {

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

                ReplyError(AConnection, CReply::unauthorized, "Unauthorized.");
            } catch (jwt::token_expired_exception &e) {
                ReplyError(AConnection, CReply::forbidden, e.what());
            } catch (jwt::token_verification_exception &e) {
                ReplyError(AConnection, CReply::bad_request, e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CReply::bad_request, e.what());
            } catch (std::exception &e) {
                ReplyError(AConnection, CReply::bad_request, e.what());
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::DoProxy(CHTTPServerConnection *AConnection) {

            auto LRequest = AConnection->Request();
            auto LReply = AConnection->Reply();

            LReply->ContentType = CReply::json;

            auto LProxy = GetProxy(AConnection);
            auto LProxyRequest = LProxy->Request();

            const auto& clientId = LRequest->FormData.Values("clientId");

            const auto& LProfile = LRequest->Params["profile"];
            const auto& profile = LProfile.IsEmpty() ? "main" : LProfile;

            const auto& uri = m_Profile[profile].Value()["uri"];
            const auto& userName = m_Profile[profile].Value()["username"];
            const auto& password = m_Profile[profile].Value()["password"];

            CStringList LRouts;
            SplitColumns(LRequest->Location.pathname, LRouts, '/');

            if (LRouts.Count() < 2) {
                AConnection->SendStockReply(CReply::not_found);
                return;
            }

            if (uri.IsEmpty()) {
                AConnection->SendStockReply(CReply::bad_request);
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
            AConnection->Data().Values("clientId", clientId);

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

            CRequest::Prepare(LProxyRequest, LRequest->Method.c_str(), Location.pathname.c_str(), LContentType.c_str());

            DebugRequest(LProxyRequest);

            LProxy->Active(true);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::Initialization(CModuleProcess *AProcess) {

            m_Profile.AddPair("main", CStringList());
            m_Profile.AddPair("test", CStringList());

            auto& mainConfig = m_Profile["main"].Value();
            auto& testConfig = m_Profile["test"].Value();

            mainConfig.AddPair("uri", Config()->IniFile().ReadString("sba/main", "uri", "https://securepayments.sberbank.ru"));
            mainConfig.AddPair("username", Config()->IniFile().ReadString("sba/main", "username", ""));
            mainConfig.AddPair("password", Config()->IniFile().ReadString("sba/main", "password", ""));

            testConfig.AddPair("uri", Config()->IniFile().ReadString("sba/test", "uri", "https://3dsec.sberbank.ru"));
            testConfig.AddPair("username", Config()->IniFile().ReadString("sba/test", "username", ""));
            testConfig.AddPair("password", Config()->IniFile().ReadString("sba/test", "password", ""));

            CApostolModule::Initialization(AProcess);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CSBAcquiring::Heartbeat() {
            CApostolModule::Heartbeat();
            m_ProxyManager.CleanUp();
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool("worker/sba", "enable", false) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CSBAcquiring::CheckConnection(CHTTPServerConnection *AConnection) {
            const auto& Location = AConnection->Request()->Location;
            return Location.pathname.SubString(0, 5) == _T("/sba/") || Location.pathname.SubString(0, 10) == _T("/sberbank/");
        }
    }
}
}