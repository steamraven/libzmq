/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "platform.hpp"

#ifdef HAVE_LIBSODIUM

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "curve_client.hpp"
#include "wire.hpp"

zmq::curve_client_t::curve_client_t (session_base_t *session_, 
                                     const std::string &peer_address_,
                                     const options_t &options_) :
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_),
    state (send_hello),
    cn_nonce(1),
    cn_peer_nonce(1),
    metadata_size(0),
    curve_1_1(false),
    sync()
{
    memcpy (public_key, options_.curve_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy (secret_key, options_.curve_secret_key, crypto_box_SECRETKEYBYTES);
    memcpy (server_key, options_.curve_server_key, crypto_box_PUBLICKEYBYTES);
    scoped_lock_t lock (sync);
#if defined(HAVE_TWEETNACL)
    // allow opening of /dev/urandom
    unsigned char tmpbytes[4];
    randombytes(tmpbytes, 4);
#else
    // todo check return code
    sodium_init();
#endif
    // check for client side checking of server cert
    if (options.zap_curve_enable_metadata) {
      if ( session->zap_connect () == 0) {
        curve_1_1 = true;
      }
    }
}

zmq::curve_client_t::~curve_client_t ()
{
}

int zmq::curve_client_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case send_hello:
            rc = produce_hello (msg_);
            if (rc == 0) {
                if (curve_1_1) {
                    state = expect_welcome_or_metadata;
                }
                else {
                    state = expect_welcome;
                }
            }
            break;
        case send_big_hello:
            rc = produce_hello (msg_);
            if (rc == 0) {
                state = expect_metadata;
            }
            break;
        case send_final_hello:
            rc = produce_hello (msg_);
            if (rc == 0) {
                state = expect_welcome;
            }
            break;
        
        case send_initiate:
            rc = produce_initiate (msg_);
            if (rc == 0) {
                state = expect_ready;
            }
            break;
        default:
            errno = EAGAIN;
            rc = -1;
    }
    return rc;
}

int zmq::curve_client_t::process_handshake_command (msg_t *msg_)
{
    const unsigned char *msg_data =
        static_cast <unsigned char *> (msg_->data ());
    const size_t msg_size = msg_->size ();

    int rc = 0;

    if (msg_size >= 6 && !memcmp (msg_data, "\5ERROR", 6)) {
        rc = process_error (msg_data, msg_size);
    }
    else {
        switch (state) {
            case expect_welcome_or_metadata:
                if (msg_size >= 8 && !memcmp (msg_data, "\7WELCOME", 8)) {
                    rc = process_welcome (msg_data, msg_size);
                }
                else 
                if (msg_size >= 9 && !memcmp (msg_data, "\x08METADATA", 9)) {
                    rc = process_metadata_size(msg_data, msg_size);
                }
                else {
                    errno = EPROTO;
                    rc = -1;
                }
                break;
            case expect_metadata:
                rc = process_metadata(msg_data, msg_size);
                break;
            case expect_welcome:
                rc = process_welcome(msg_data, msg_size);
                break;
            case expect_ready:
                rc = process_ready (msg_data, msg_size);
                break;
            default:
                //  Temporary support for security debugging
                puts ("CURVE I: invalid handshake command");
                errno = EPROTO;
                rc = -1;
                break;
        }
    }

    if (rc == 0) {
        rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    return rc;
}

int zmq::curve_client_t::encode (msg_t *msg_)
{
    zmq_assert (state == connected);

    uint8_t flags = 0;
    if (msg_->flags () & msg_t::more)
        flags |= 0x01;

    uint8_t message_nonce [crypto_box_NONCEBYTES];
    memcpy (message_nonce, "CurveZMQMESSAGEC", 16);
    put_uint64 (message_nonce + 16, cn_nonce);

    const size_t mlen = crypto_box_ZEROBYTES + 1 + msg_->size ();

    uint8_t *message_plaintext = static_cast <uint8_t *> (malloc (mlen));
    alloc_assert (message_plaintext);

    memset (message_plaintext, 0, crypto_box_ZEROBYTES);
    message_plaintext [crypto_box_ZEROBYTES] = flags;
    memcpy (message_plaintext + crypto_box_ZEROBYTES + 1,
            msg_->data (), msg_->size ());

    uint8_t *message_box = static_cast <uint8_t *> (malloc (mlen));
    alloc_assert (message_box);

    int rc = crypto_box_afternm (message_box, message_plaintext,
                                 mlen, message_nonce, cn_precom);
    zmq_assert (rc == 0);

    rc = msg_->close ();
    zmq_assert (rc == 0);

    rc = msg_->init_size (16 + mlen - crypto_box_BOXZEROBYTES);
    zmq_assert (rc == 0);

    uint8_t *message = static_cast <uint8_t *> (msg_->data ());

    memcpy (message, "\x07MESSAGE", 8);
    memcpy (message + 8, message_nonce + 16, 8);
    memcpy (message + 16, message_box + crypto_box_BOXZEROBYTES,
            mlen - crypto_box_BOXZEROBYTES);

    free (message_plaintext);
    free (message_box);

    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::decode (msg_t *msg_)
{
    zmq_assert (state == connected);

    if (msg_->size () < 33) {
        errno = EPROTO;
        return -1;
    }

    const uint8_t *message = static_cast <uint8_t *> (msg_->data ());
    if (memcmp (message, "\x07MESSAGE", 8)) {
        errno = EPROTO;
        return -1;
    }

    uint8_t message_nonce [crypto_box_NONCEBYTES];
    memcpy (message_nonce, "CurveZMQMESSAGES", 16);
    memcpy (message_nonce + 16, message + 8, 8);
    uint64_t nonce = get_uint64(message + 8);
    if (nonce <= cn_peer_nonce) {
        errno = EPROTO;
        return -1;
    }
    cn_peer_nonce = nonce;


    const size_t clen = crypto_box_BOXZEROBYTES + (msg_->size () - 16);

    uint8_t *message_plaintext = static_cast <uint8_t *> (malloc (clen));
    alloc_assert (message_plaintext);

    uint8_t *message_box = static_cast <uint8_t *> (malloc (clen));
    alloc_assert (message_box);

    memset (message_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (message_box + crypto_box_BOXZEROBYTES,
            message + 16, msg_->size () - 16);

    int rc = crypto_box_open_afternm (message_plaintext, message_box,
                                      clen, message_nonce, cn_precom);
    if (rc == 0) {
        rc = msg_->close ();
        zmq_assert (rc == 0);

        rc = msg_->init_size (clen - 1 - crypto_box_ZEROBYTES);
        zmq_assert (rc == 0);

        const uint8_t flags = message_plaintext [crypto_box_ZEROBYTES];
        if (flags & 0x01)
            msg_->set_flags (msg_t::more);

        memcpy (msg_->data (),
                message_plaintext + crypto_box_ZEROBYTES + 1,
                msg_->size ());
    }
    else
        errno = EPROTO;

    free (message_plaintext);
    free (message_box);

    return rc;
}

int zmq::curve_client_t::zap_msg_available ()
{
    if (state != expect_zap_reply) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0) {
        if (status_code == "200") {
            state = send_final_hello;  
        }
        else {
            errno = EPROTO;
            return -1;
        }
    }
    return rc;
}

zmq::mechanism_t::status_t zmq::curve_client_t::status () const
{
    if (state == connected)
        return mechanism_t::ready;
    else
    if (state == error_received)
        return mechanism_t::error;
    else
        return mechanism_t::handshaking;
}

int zmq::curve_client_t::produce_hello (msg_t *msg_)
{
    uint8_t hello_nonce [crypto_box_NONCEBYTES];
    uint8_t hello_plaintext [crypto_box_ZEROBYTES + 64];
    uint8_t hello_box [crypto_box_BOXZEROBYTES + 80];

    uint32_t extra_zeros = std::max(metadata_size + 45 - 200,(uint32_t) 0);

    //  Generate new short-term key pair for each hello
    int rc = crypto_box_keypair (cn_public, cn_secret);
    zmq_assert (rc == 0);

    //  Prepare the full nonce
    memcpy (hello_nonce, "CurveZMQHELLO---", 16);
    put_uint64 (hello_nonce + 16, cn_nonce);

    //  Create Box [64 * %x0](C'->S)
    memset (hello_plaintext, 0, sizeof hello_plaintext);

    rc = crypto_box (hello_box, hello_plaintext,
                         sizeof hello_plaintext,
                         hello_nonce, server_key, cn_secret);
    zmq_assert (rc == 0);

    rc = msg_->init_size (200 + extra_zeros);
    errno_assert (rc == 0);
    uint8_t *hello = static_cast <uint8_t *> (msg_->data ());

    memcpy (hello, "\x05HELLO", 6);
    //  CurveZMQ major and minor version numbers
    if (curve_1_1) {
            memcpy (hello + 6, "\1\1", 2);
    }
    else {
            memcpy (hello + 6, "\1\0", 2);
    }
    //  Anti-amplification padding
    memset (hello + 8, 0, 72);
    //  Client public connection key
    memcpy (hello + 80, cn_public, crypto_box_PUBLICKEYBYTES);
    //  Short nonce, prefixed by "CurveZMQHELLO---"
    memcpy (hello + 112, hello_nonce + 16, 8);
    //  Signature, Box [64 * %x0](C'->S)
    memcpy (hello + 120, hello_box + crypto_box_BOXZEROBYTES, 80);
    // extra zeros
    memset (hello + 200, 0, extra_zeros);

    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::process_metadata_size (
        const uint8_t *msg_data, size_t msg_size )
{

    if (msg_size > 200 || msg_size < 45) {
        //  Temporary support for security debugging
        puts ("CURVE II: server METADATA is not correct size");
        errno = EPROTO;
        return -1;
    }

    if (memcmp (msg_data, "\x08METADATA", 9)) {
        //  Temporary support for security debugging
        puts ("CURVE II: server METADATA has invalid command name");
        errno = EPROTO;
        return -1;
    }
    metadata_size = get_uint32(msg_data + 9);
    if (options.zmtp_max_metadata_size >= 0) {
        metadata_size = std::min(metadata_size, (uint32_t) options.zmtp_max_metadata_size);
    }
        
    if (metadata_size <= 200 - 45) {
        return process_metadata(msg_data, msg_size);
    }
   
    state = send_big_hello;
    return 0;
}

int zmq::curve_client_t::process_metadata (
        const uint8_t *msg_data, size_t msg_size)
{

    if (msg_size != 200 and msg_size != metadata_size + 45) {
        //  Temporary support for security debugging
        puts ("CURVE III: server full METADATA is not correct size");
        errno = EPROTO;
        return -1;
    }

    if (memcmp (msg_data, "\x08METADATA", 9)) {
        //  Temporary support for security debugging
        puts ("CURVE III: server full METADATA has invalid command name");
        errno = EPROTO;
        return -1;
    }
    //metadata_size = std::min(get_uint32(metadata + 9), options.zmpt_max_metadata_size);
    memcpy (server_key, msg_data+9+4, crypto_box_PUBLICKEYBYTES);

     //ZAP

    send_zap_request(server_key, msg_data+9+4+crypto_box_PUBLICKEYBYTES, metadata_size);
    int rc = receive_and_process_zap_reply ();
    if (rc == 0) {
        if (status_code == "200") {
            state = send_final_hello;
        }
        else {
            errno = EPROTO;
            return -1;
        }
    }
    else
    if (errno == EAGAIN)
        state = expect_zap_reply;
    else
        return -1;

    // parse_metadata??
    return 0;
}


int zmq::curve_client_t::process_welcome (
        const uint8_t *msg_data, size_t msg_size)
{
    if (msg_size != 168) {
        errno = EPROTO;
        return -1;
    }

    if (memcmp (msg_data, "\x07WELCOME", 8)) {
        //  Temporary support for security debugging
        puts ("CURVE I: server WELCOME has invalid command name");
        errno = EPROTO;
        return -1;
    }

    uint8_t welcome_nonce [crypto_box_NONCEBYTES];
    uint8_t welcome_plaintext [crypto_box_ZEROBYTES + 128];
    uint8_t welcome_box [crypto_box_BOXZEROBYTES + 144];

    //  Open Box [S' + cookie](C'->S)
    memset (welcome_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (welcome_box + crypto_box_BOXZEROBYTES, msg_data + 24, 144);

    memcpy (welcome_nonce, "WELCOME-", 8);
    memcpy (welcome_nonce + 8, msg_data + 8, 16);

    int rc = crypto_box_open (welcome_plaintext, welcome_box,
                              sizeof welcome_box,
                              welcome_nonce, server_key, cn_secret);
    if (rc != 0) {
        errno = EPROTO;
        return -1;
    }

    memcpy (cn_server, welcome_plaintext + crypto_box_ZEROBYTES, 32);
    memcpy (cn_cookie, welcome_plaintext + crypto_box_ZEROBYTES + 32, 16 + 80);

    //  Message independent precomputation
    rc = crypto_box_beforenm (cn_precom, cn_server, cn_secret);
    zmq_assert (rc == 0);

    state = send_initiate;

    return 0;
}

int zmq::curve_client_t::produce_initiate (msg_t *msg_)
{
    uint8_t vouch_nonce [crypto_box_NONCEBYTES];
    uint8_t vouch_plaintext [crypto_box_ZEROBYTES + 64];
    uint8_t vouch_box [crypto_box_BOXZEROBYTES + 80];

    //  Create vouch = Box [C',S](C->S')
    memset (vouch_plaintext, 0, crypto_box_ZEROBYTES);
    memcpy (vouch_plaintext + crypto_box_ZEROBYTES, cn_public, 32);
    memcpy (vouch_plaintext + crypto_box_ZEROBYTES + 32, server_key, 32);

    memcpy (vouch_nonce, "VOUCH---", 8);
    randombytes (vouch_nonce + 8, 16);

    int rc = crypto_box (vouch_box, vouch_plaintext,
                         sizeof vouch_plaintext,
                         vouch_nonce, cn_server, secret_key);
    zmq_assert (rc == 0);

    //  Assume here that metadata is limited to 256 bytes
    uint8_t initiate_nonce [crypto_box_NONCEBYTES];
    uint8_t initiate_plaintext [crypto_box_ZEROBYTES + 128 + 256];
    uint8_t initiate_box [crypto_box_BOXZEROBYTES + 144 + 256];

    //  Create Box [C + vouch + metadata](C'->S')
    memset (initiate_plaintext, 0, crypto_box_ZEROBYTES);
    memcpy (initiate_plaintext + crypto_box_ZEROBYTES,
            public_key, 32);
    memcpy (initiate_plaintext + crypto_box_ZEROBYTES + 32,
            vouch_nonce + 8, 16);
    memcpy (initiate_plaintext + crypto_box_ZEROBYTES + 48,
            vouch_box + crypto_box_BOXZEROBYTES, 80);

    //  Metadata starts after vouch
    uint8_t *ptr = initiate_plaintext + crypto_box_ZEROBYTES + 128;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, "Socket-Type", socket_type, strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ
    ||  options.type == ZMQ_DEALER
    ||  options.type == ZMQ_ROUTER)
        ptr += add_property (ptr, "Identity", options.identity, options.identity_size);

    const size_t mlen = ptr - initiate_plaintext;

    memcpy (initiate_nonce, "CurveZMQINITIATE", 16);
    put_uint64 (initiate_nonce + 16, cn_nonce);

    rc = crypto_box (initiate_box, initiate_plaintext,
                     mlen, initiate_nonce, cn_server, cn_secret);
    zmq_assert (rc == 0);

    rc = msg_->init_size (113 + mlen - crypto_box_BOXZEROBYTES);
    errno_assert (rc == 0);

    uint8_t *initiate = static_cast <uint8_t *> (msg_->data ());

    memcpy (initiate, "\x08INITIATE", 9);
    //  Cookie provided by the server in the WELCOME command
    memcpy (initiate + 9, cn_cookie, 96);
    //  Short nonce, prefixed by "CurveZMQINITIATE"
    memcpy (initiate + 105, initiate_nonce + 16, 8);
    //  Box [C + vouch + metadata](C'->S')
    memcpy (initiate + 113, initiate_box + crypto_box_BOXZEROBYTES,
            mlen - crypto_box_BOXZEROBYTES);
    cn_nonce++;

    return 0;
}

int zmq::curve_client_t::process_ready (
        const uint8_t *msg_data, size_t msg_size)
{
    const uint32_t MACBYTES = crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES;

    if (msg_size < 30 && msg_size > 14 + MACBYTES + 256) {
        errno = EPROTO;
        return -1;
    }

    if (memcmp (msg_data, "\x05READY", 6)) {
        //  Temporary support for security debugging
        puts ("CURVE I: server READY has invalid command name");
        errno = EPROTO;
        return -1;
    }

    const size_t clen = (msg_size - 14) + crypto_box_BOXZEROBYTES;

    uint8_t ready_nonce [crypto_box_NONCEBYTES];
    uint8_t ready_plaintext [crypto_box_ZEROBYTES + 256];
    uint8_t ready_box [crypto_box_BOXZEROBYTES + 16 + 256];

    memset (ready_box, 0, crypto_box_BOXZEROBYTES);
    memcpy (ready_box + crypto_box_BOXZEROBYTES,
            msg_data + 14, clen - crypto_box_BOXZEROBYTES);

    memcpy (ready_nonce, "CurveZMQREADY---", 16);
    memcpy (ready_nonce + 16, msg_data + 6, 8);
    cn_peer_nonce = get_uint64(msg_data + 6);

    int rc = crypto_box_open_afternm (ready_plaintext, ready_box,
                                      clen, ready_nonce, cn_precom);

    if (rc != 0) {
        errno = EPROTO;
        return -1;
    }

    rc = parse_metadata (ready_plaintext + crypto_box_ZEROBYTES,
                         clen - crypto_box_ZEROBYTES);
    if (rc == 0)
        state = connected;

    return rc;
}

int zmq::curve_client_t::process_error (
        const uint8_t *msg_data, size_t msg_size)
{
    if (state != expect_welcome && state != expect_ready) {
        errno = EPROTO;
        return -1;
    }
    if (msg_size < 7) {
        errno = EPROTO;
        return -1;
    }
    const size_t error_reason_len = static_cast <size_t> (msg_data [6]);
    if (error_reason_len > msg_size - 7) {
        errno = EPROTO;
        return -1;
    }
    state = error_received;
    return 0;
}


void zmq::curve_client_t::send_zap_request (const uint8_t *key, const uint8_t *metadata, const uint32_t metadata_size)
{
    int rc;
    msg_t msg;

    //  Address delimiter frame
    rc = msg.init ();
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Version frame
    rc = msg.init_size (3);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1.0", 3);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Request ID frame
    rc = msg.init_size (1);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1", 1);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Domain frame
    rc = msg.init_size (options.zap_domain.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), options.zap_domain.c_str (), options.zap_domain.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Address frame
    rc = msg.init_size (peer_address.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), peer_address.c_str (), peer_address.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Identity frame
    rc = msg.init_size (options.identity_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), options.identity, options.identity_size);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Mechanism frame
    rc = msg.init_size (5);
    errno_assert (rc == 0);
    memcpy (msg.data (), "CURVE", 5);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Credentials frame
    rc = msg.init_size (crypto_box_PUBLICKEYBYTES);
    errno_assert (rc == 0);
    memcpy (msg.data (), key, crypto_box_PUBLICKEYBYTES);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    // Metadata frame
    rc = msg.init_size(metadata_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), metadata, metadata_size);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);
}

int zmq::curve_client_t::receive_and_process_zap_reply ()
{
    int rc = 0;
    msg_t msg [7];  //  ZAP reply consists of 7 frames

    //  Initialize all reply frames
    for (int i = 0; i < 7; i++) {
        rc = msg [i].init ();
        errno_assert (rc == 0);
    }

    for (int i = 0; i < 7; i++) {
        rc = session->read_zap_msg (&msg [i]);
        if (rc == -1)
            break;
        if ((msg [i].flags () & msg_t::more) == (i < 6? 0: msg_t::more)) {
            //  Temporary support for security debugging
            puts ("CURVE I: ZAP handler sent incomplete reply message");
            errno = EPROTO;
            rc = -1;
            break;
        }
    }

    if (rc != 0)
        goto error;

    //  Address delimiter frame
    if (msg [0].size () > 0) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler sent malformed reply message");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Version frame
    if (msg [1].size () != 3 || memcmp (msg [1].data (), "1.0", 3)) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler sent bad version number");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Request id frame
    if (msg [2].size () != 1 || memcmp (msg [2].data (), "1", 1)) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler sent bad request ID");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Status code frame
    if (msg [3].size () != 3) {
        //  Temporary support for security debugging
        puts ("CURVE I: ZAP handler rejected client authentication");
        errno = EACCES;
        rc = -1;
        goto error;
    }

    //  Save status code
    status_code.assign (static_cast <char *> (msg [3].data ()), 3);

    //  Save user id
    set_user_id (msg [5].data (), msg [5].size ());

    //  Process metadata frame
    rc = parse_metadata (static_cast <const unsigned char*> (msg [6].data ()),
                         msg [6].size (), true);

error:
    for (int i = 0; i < 7; i++) {
        const int rc2 = msg [i].close ();
        errno_assert (rc2 == 0);
    }

    return rc;
}



#endif
