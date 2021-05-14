/*++

Program name:

  Apostol Web Service

Module Name:

  SBAcquiring.hpp

Notices:

  Module: Sberbank Acquiring

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_ACQUIRING_HPP
#define APOSTOL_ACQUIRING_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Workers {

        //--------------------------------------------------------------------------------------------------------------

        //-- CSBAcquiring ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CSBAcquiring: public CApostolModule {
        private:

            CHTTPProxyManager m_ProxyManager;

            CStringListPairs m_Profiles;

            void InitMethods() override;

            void AuthorizedFetch(CHTTPServerConnection *AConnection, const CString &Token, const CString &Method,
                const CString &Path, const CJSON &Payload, const CString &Agent);

            static bool CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization);

            void VerifyToken(const CString &Token);

            CHTTPProxy *GetProxy(CHTTPServerConnection *AConnection);

        protected:

            void DoProxy(CHTTPServerConnection *AConnection);

            void DoVerbose(CSocketEvent *Sender, CTCPConnection *AConnection, LPCTSTR AFormat, va_list args);
            bool DoProxyExecute(CTCPConnection *AConnection);
            void DoProxyException(CTCPConnection *AConnection, const Delphi::Exception::Exception &E);
            void DoEventHandlerException(CPollEventHandler *AHandler, const Delphi::Exception::Exception &E);

            void DoProxyConnected(CObject *Sender);
            void DoProxyDisconnected(CObject *Sender);

        public:

            explicit CSBAcquiring(CModuleProcess *AProcess);

            ~CSBAcquiring() override = default;

            static class CSBAcquiring *CreateModule(CModuleProcess *AProcess) {
                return new CSBAcquiring(AProcess);
            }

            bool CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);

            static void InitConfig(const CIniFile &IniFile, const CString &Profile, CStringList &Config);

            void Initialization(CModuleProcess *AProcess) override;

            void Heartbeat() override;

            bool Enabled() override;
            bool CheckLocation(const CLocation &Location) override;

        };
    }
}

using namespace Apostol::Workers;
}
#endif //APOSTOL_ACQUIRING_HPP
