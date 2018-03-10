//! a client for the XMPP protocol

import Public.Protocols.XMPP;

#if JABBER_DEBUG
#define WERROR(X) werror("XMPP.client():" + X)
#else
#define WERROR(X)
#endif

#if JABBER_IO_DEBUG
#define JABBER_IO_WERROR(X) werror("XMPP.client(IO):" + X)
#else
#define JABBER_IO_WERROR(X)
#endif

//! Context for SSL connections
SSL.Context ssl_ctx;

int is_background;
string stream;
string url;
int sslcon=0;
string server, host; // server = url portion, host = resolved srv hostname.
int port;
string user;
string password;

string sessionid="";
string jid;
int negotiation_complete = 0;
string selected_mechanism;
multiset attempted_mechanisms = (<>);

mapping presence=([]);
mapping roster=([]);

protected object conn;
protected object messages=ADT.Queue();

protected function message_callback;
protected function subscribe_callback;
protected function unsubscribe_callback;
protected function subscribed_callback;
protected function unsubscribed_callback;
protected function presence_callback;
protected function disconnect_callback;
protected function roster_callback;
protected function connect_callback;

protected string _client_name;

protected string write_buf = "";

//! sets the client name to be used in the connection to the XMPP server.
//! defaults to a random UUID.
void set_client_name(string c)
{
   if(stringp(c))
     _client_name=c;
}

//! returns the client name in use.
string get_client_name()
{
  return _client_name;
}

//! sets the function to be called when a session is disconnected.
//! 
//! the callback receives the client as an argument.
void set_disconnect_callback(function f)
{
  if(functionp(f))
  {
     disconnect_callback=f;
  }
}

//! sets the function to be called when a session is connected.
//!
//! the callback receives the client as an argument.
void set_connect_callback(function f) 
{
  if(functionp(f))
  {
    connect_callback = f;
  }
}


//! sets the function to be called when a user's precence info changes.
//! 
//! the callback function will receive a mapping containing the
//! contents of the presnece update
void set_presence_callback(function f)
{
  if(functionp(f))
  {
     presence_callback=f;
  }
}

//! sets the function to be called when the roster changes.
//! 
//! the callback function will receive a mapping containing the
//! contents of the roster change
void set_roster_callback(function f)
{
  if(functionp(f))
  {
     roster_callback=f;
  }
}


//! sets the function to be called when a message is received.
//! 
//! the callback function will receive a mapping containing the
//! contents of the message along with header information
void set_message_callback(function f)
{
  if(functionp(f))
  {
     message_callback=f;
  }
}

//! sets the function to be called when a subscribe request is received.
//! 
//! the callback function will receive a string containing the
//! XMPP ID making the request. the function should return a boolean
//! indicating whether the request should be accepted (true=accept)
void set_subscribe_callback(function f)
{
  if(functionp(f))
  {
     subscribe_callback=f;
  }
}

//! sets the function to be called when an unsubscribe request is received.
//! 
//! the callback function will receive a string containing the
//! XMPP ID making the request. the function should return a boolean
//! indicating whether the request should be accepted (true=accept)
void set_unsubscribe_callback(function f)
{
  if(functionp(f))
  {
     unsubscribe_callback=f;
  }
}

//! sets the function to be called when a subscribed notification is received.
//! 
//! the callback function will receive a string containing the
//! XMPP ID making the request.
void set_subscribed_callback(function f)
{
  if(functionp(f))
  {
     subscribed_callback=f;
  }
}

//! sets the function to be called when a unsubscribed notification is received.
//! 
//! the callback function will receive a string containing the
//! XMPP ID making the request.
void set_unsubscribed_callback(function f)
{
  if(functionp(f))
  {
     unsubscribed_callback=f;
  }
}

//! clears any disconnect callback
void clear_disconnect_callback()
{
   disconnect_callback=0;
}

//! clears any connect callback
void clear_connect_callback() 
{
  connect_callback = 0;
}

//! clears any presence callback
void clear_presence_callback()
{
   presence_callback=0;
}


//! clears any roster callback
void clear_roster_callback()
{
   roster_callback=0;
}

//! clears any message callback
void clear_message_callback()
{
   message_callback=0;
}

//! clears any subscribe callback
void clear_subscribe_callback()
{
   subscribe_callback=0;
}

//! clears any unsubscribe callback
void clear_unsubscribe_callback()
{
   unsubscribe_callback=0;
}

//! clears any subscribed notification callback
void clear_subscribed_callback()
{
   subscribed_callback=0;
}

//! clears any unsubscribed notification callback
void clear_unsubscribed_callback()
{
   unsubscribed_callback=0;
}

//! returns an array of messages waiting to be received.
//! if a message callback is being used, delivery to the incoming message
//! queue is disabled, though any unreceived messages will be stored
//! for pickup later.
array get_messages()
{
  array m=({});
  while(!messages->is_empty())
    m+=({messages->get()});
  return m;
}

protected array decode_url(string url) {
  string _prot,_server,_user,_password, tmp;
  int _port;
  int _use_ssl=0;
 
  int matches=0;

  WERROR("url: " + url + "\n");

  matches=sscanf(url, "%s://%s", _prot, _server);
 
  if(matches!=2) 
    error("xmpp url " + url + " invalid.");

  if(_prot=="xmpps") _use_ssl=1;
  else if(_prot!="xmpp") 
    error("unknown protocol " + _prot + ".");

  matches=sscanf(_server, "%s@%s", _user, tmp);

  if(matches==2)
  {
    sscanf(_user, "%s:%s", _user, _password);
    _server=tmp;
  }

  matches=sscanf(_server, "%s:%d", _server, _port);

  if(matches!=2)
  {
     if(_use_ssl==1)
       _port=5223;
     else _port=5222;
  }

  return ({_server, _port, _user, _password, _use_ssl});

}

//! create a new client connection to server url, using a xmpp url
//! 
//! following creation, there will be a connection to the server but
//! the session will not yet be initiated. see @[begin] and @[authenticate]
//!
//! @param ctx
//!   an optional context for an SSL connection to the XMPP server.  
//!
//! @example
//!  xmpp://user:pass@@xmppserver.fqdn
void create(string url, void|SSL.Context ctx)
{
  string _server,_user,_password;
  int _ssl,_port;
  attempted_mechanisms = (<>);

  [_server, _port, _user, _password, _ssl]=decode_url(url);

      if(!ctx)
      ctx = SSL.Context();

    ssl_ctx = ctx;
  server = _server;
  object client = Protocols.DNS.client();
  string pdu =  client->mkquery("_xmpp-client._tcp." + _server, Protocols.DNS.C_IN, Protocols.DNS.T_SRV);
  mapping result = client->do_sync_query(pdu);
//  werror("SRV record for " + _server + ": %O", result);

  if(result && result->an) {
    mapping srv = result->an[0];
    host = srv->target;
    port = srv->port;    
    
  }
  else {
    throw(Error.Generic("Unable to find a server for " + _server + ".\n"));
  }
    conn=Stdio.File();
    conn->set_blocking();
    WERROR(sprintf("connecting to %O on port %O\n", host, (int)port));
    if(!conn->connect("45.76.82.177" /*server*/, (int)port))
      throw(Error.Generic("unable to connect to xmpp server at " + host + " port " + port + ".\n"));
  WERROR("connected.\n");
  if(_ssl) // are we using ssl?
  {
    WERROR("using ssl.\n");
    object _c;
    _c = conn;

    conn = SSL.File(_c, ctx);
    conn->set_blocking();
    if(!conn->connect())
      throw(Error.Generic("Unable to initiate SSL connection.\n"));
    sslcon = 1;
  }

  conn->set_close_callback(conn_closed);

  user=_user;
  password=_password;

}

void do_starttls() {
      WERROR("using ssl.\n");
    object _c;
    _c = conn;

    conn = SSL.File(_c, ssl_ctx);
    conn->set_blocking();
    if(!conn->connect())
      throw(Error.Generic("Unable to initiate SSL connection.\n"));
    sslcon = 1;

    conn->set_close_callback(conn_closed);
    call_out(begin, 0);
}

//! sets the xmpp identity of the client.
//! normally this information is automatically pulled from
//! the xmpp connect url, however in situations where the server
//! name is different from the xmpp domain name, this method
//! may be used to specify the full xmpp user identity.
//!
//! @param xmpp_id
//!   the xmpp identity, in the form of username or username@somdomain
void set_user_identity(string xmpp_id)
{
  if(search(xmpp_id, "@") == -1)
  {
    user = xmpp_id;
  }
  else
  {
     sscanf(xmpp_id, "%s@%s", user, server);
  }

  WERROR("USER set to " + user + ".\n");
  WERROR("HOST set to " + server + ".\n");

}

void set_username(string _username) {
  user = _username;
}

void set_password(string _password) {
  password = _password;
}

//! creates a new xmpp session and sets the mode to blocking.
//! 
void begin()
{
  get_new_session();
  set_background_mode(1);
}

protected void conn_closed()
{
  if(disconnect_callback)
    call_function(disconnect_callback, this);
}

protected string make_stream(string s)
{
  if(search(s, "</stream:stream>") == -1)
    s = s + "</stream:stream>";
  if(search(s, "<stream:stream") == -1)
    s = stream + s;
  return s;
}

protected int|string check_for_autherrors(string s)
{
  object node;

  node=Parser.XML.NSTree->parse_input(s);
  _auth_error=0;
  
  if(node->walk_preorder(low_checkforautherrors)==Parser.XML.NSTree.STOP_WALK 
    && _auth_error==1)
      return _error;
  _auth_error=0;
  return 0;  
  
}

protected object|string check_for_errors(string s)
{
  object node;
  mixed e;
  s = make_stream(s);
  JABBER_IO_WERROR("parsing " + s + "\n");
  e=catch(
    node=Parser.XML.NSTree.parse_input(s)
  );

//werror("tree: " + Parser.XML.NSTree.visualize(node));
  if(e)
  {
    WERROR(sprintf("error parsing %O %O.\n", e[0], (s)));
    return e[0];
  }
  
  if(node->walk_preorder(low_checkforerrors)==Parser.XML.NSTree.STOP_WALK)
      return _error;
  return node;
}

private string _error;

protected void|int low_checkforerrors(object node)
{
  if(node->get_tag_name()=="error")
  {
    _error= node->value_of_node();
    return Parser.XML.NSTree.STOP_WALK; 
  } else if (node->get_tag_name() == "iq" && node->get_attributes()->type == "error") {
    _error= node->value_of_node();
    return Parser.XML.NSTree.STOP_WALK;
  }
}

private int _auth_error;

protected void|int low_checkforautherrors(object node)
{
  if(node->get_tag_name()=="iq" && node->get_attributes()->type!="error")
  {
    return Parser.XML.NSTree.STOP_WALK;
  }

  if(node->get_tag_name()=="error")
  {
    _error= node->value_of_node();
    _auth_error=1;
    return Parser.XML.NSTree.STOP_WALK; 
  }
}

//! send message m with subject s to user u
int send_message(string m, string s, string u)
{
  string msg="<message to='" + u + "' "
     // "from='" + user + "@" + server + "/" 
     //     + _client_name + "'"
      ">\n"
     "<subject>" + s + "</subject>\n"
     "<body>" + m + "</body>\n"
     "</message>";

  send_msg(msg);
  return 1;
}

//!
int respond_subscribed(string who)
{ 
  string msg="";

  msg+="<presence to='" + who + "' type='subscribed'/>";
  
  send_msg(msg);
}

//!
int respond_unsubscribed(string who)
{ 
  string msg="";

  msg+="<presence to='" + who + "' type='unsubscribed'/>";
  
  send_msg(msg);
}

//!
int request_roster()
{
  string msg="";

  msg+="<iq type='get' id='roster_1'><query xmlns='jabber:iq:roster'/></iq>";

  send_msg(msg);
}

//!
int request_remove(string who)
{
  string msg="";

  msg+="<iq type='set' id='remove1'><query xmlns='jabber:iq:roster'>"
    "<item jid='" + who  + "' subscription='remove'/></query></iq>";

  send_msg(msg);
}

//!
int request_subscribe(string who, string nick, string roster)
{
  string msg="";

  msg+="<iq type='set'><query xmlns='jabber:iq:roster'>";
  msg+="<item jid='" + who + "' name='" + nick +"'>";
  msg+="<group>" + roster + "</group>";
  msg+="</item>";
  msg+="</query></iq>";
  msg+="<presence to='" + who + "' type='subscribe'/>";

  send_msg(msg);
}


int request_unsubscribe(string who)
{
  string msg="";

  msg+="<presence type='unsubscribe' to='" + who + "' />";

  send_msg(msg);
}

//! set presence of the logged in user
//! @param show
//!   should be one of @[PRESENCE_AWAY],
//!   @[PRESENCE_CHAT], @[PRESENCE_DND] or @[PRESENCE_XA].
//! @param status
//!   an optional string containing a status message
//! @param priority
//!   an optional priority setting (see XMPP spec for details)
//! @note
//!   we don't use the cdata in the text because some clients
//!   don't know what to do with that. we should probably complain,
//!   as it's perfectly valid xml.
int set_presence(int show, string|void status, int|void priority)
{
  string msg="";
  msg="<presence>";

  if(show==PRESENCE_UNAVAILABLE)
    msg="<presence type='unavailable'>";
  else if(show==PRESENCE_AWAY)
    msg+="<show>away</show>";
  else if(show==PRESENCE_CHAT)
    msg+="<show>chat</show>";
  else if(show==PRESENCE_DND)
    msg+="<show>dnd</show>";
  else if(show==PRESENCE_XA)
    msg+="<show>xa</show>";
 
  if(status)
    msg+="<status>" + status + "</status>";

  msg+="<priority>" + (priority||5) + "</priority>";  
  msg+="</presence>\n";

  send_msg(msg);
  return 1;
}

//! right now we only do plaintext authentication.
//! will use user/password information gleaned from the xmpp url if
//! authentication information is not provided.
void authenticate()
{
  set_background_mode(0);

  string u = user;
  string p = password;

  string msg="<iq id='auth1' type='get'>\n"
      "    <query xmlns='jabber:iq:auth'>\n"
      "      <username>" + u + "</username>\n"
      "    </query>\n"
      "  </iq>";

  send_msg(msg);
  object node = sync_await_response();
  werror("node: %O\n", node);
//  WERROR(Parser.XML.NSTree->visualize(node));

  msg="<iq id='auth2' type='set'>"
   "<query xmlns='jabber:iq:auth'>"
   " <username>" + u + "</username>" +
   (!selected_mechanism?(" <password>" + p + "</password>"):"") +
   " <resource>" + _client_name + "</resource>"
   "</query>"
   "</iq>";

  send_msg(msg);

  node = sync_await_response();
  werror("node: %O\n", node);
  set_background_mode(1);

}

object sync_await_response() {
  set_background_mode(0);
  string rslt=conn->read(2048,1);

  JABBER_IO_WERROR("read1: " + rslt+"\n\n");
  mixed e=check_for_errors(rslt);
  if(stringp(e))
    error("Received error: " + e + "\n");
  object node=e;
//  object node=Parser.XML.NSTree->parse_input(make_stream(rslt));
  foreach(node->get_children();; object n)
    if(n->get_tag_name() == "stream")
      return n;
  else return 0;
}

//!
void disconnect()
{
   set_background_mode(0);
   string msg="</stream:stream>\n";
   send_msg(msg, 1);

   if(conn->is_open()) conn->close();
}

//!
void get_new_session()
{
  set_background_mode(0);
  string msg="<stream:stream\n"
             "  to='" + server + "'\n"
             "  version='1.0'\n"
             "  xml:lang='en'\n"
             "  xmlns='jabber:client'\n"
             "  xmlns:stream='http://etherx.jabber.org/streams'>\n";  
  send_msg(msg, 1);

  string rslt=conn->read(2048,1);
  WERROR("Read " + rslt + "\n");
  WERROR("parsing\n");
  object node;
  mixed e = catch(
    node = Parser.XML.NSTree->parse_input(rslt + "</stream:stream>")
  );
  if(e) { throw(Error.Generic(sprintf("error parsing stream: %O\n", rslt)));}
  WERROR("Node: " + sprintf("%O", node) + "\n");
  parse_stream(node);
  //stream=rslt;
  return;
}

protected int low_parse_stream(object n)
{
  string name = n->get_tag_name();
  WERROR("stream received tag " + name + "\n");
  if(name=="stream")
  {
    if(!stream) {
      n->replace_children(({}));
      stream = replace(n->render_xml(), "/>", ">");
    }
    mapping a=n->get_attributes();
    if(!a->id)     return !Parser.XML.NSTree.STOP_WALK;  
    sessionid=a->id;
    // we may have some negotiation messages, so let's check for them
    n->iterate_children(low_low_read_message);
    return Parser.XML.NSTree.STOP_WALK;  
  }
}

protected void parse_stream(object n)
{
  if(n->iterate_children(low_parse_stream) !=Parser.XML.NSTree.STOP_WALK) 
    error("Invalid stream received from server.\n");
}

//! sets the xmpp client to optionally operate in callback mode
void set_background_mode(int i)
{
  if(!conn->is_open()) throw(Error.Generic("connection is closed. unable to modify background mode.\n"));
  is_background = (i?1:0);
   if(i)
   {
      conn->set_nonblocking();
      conn->set_read_callback(low_read_message);
      conn->set_write_callback(low_write_message);
   }
   else
   {
      conn->set_blocking();
      if(write_buf && sizeof(write_buf))
      {
        int x = conn->write(write_buf);
		if(x < sizeof(write_buf))
		write_buf = write_buf[x..];
		else
          write_buf = "";
      }
   }
}

protected void low_read_message(int id, string data)
{
  WERROR("received *>>" + data + "<<*\n");
  mixed e=check_for_errors(data);
  if(stringp(e))
    error("Received error: " + e + "\n");
  object node=e;

  //
  // NOTE: we _assume_ that the stream node is a child of the root.
  // that may not be an assumption that holds universally.
  //
//  werror("node: %O\n", Parser.XML.NSTree.visualize(node));
  foreach(node->get_children();; mixed n)
  {
    if(n->get_tag_name() == "stream")
      n->iterate_children(low_low_read_message);
  }
}

protected mixed get_type_registry(object node) {
  return 0;
}

protected int low_low_read_message(object node)
{
   mixed type_registry;
   string type=node->get_tag_name();

   WERROR("got " + type +" message\n");

   if(type=="features") // we have negotiating to do
   {
      array kids = node->get_children();
      if(!kids || !sizeof(kids))
      {
        negotiation_complete = 1;
        set_background_mode(1);
        if(connect_callback) connect_callback(this);
      }
      else negotiate_features(kids);
   }

   else if(type=="message") // we have a message incoming to us.
   {
      mapping msg=([]);
      msg->timestamp=time();
      msg+=node->get_attributes();
      foreach(node->get_children(), object n)
         low_parse_message(n, msg);

      if(message_callback)
        call_function(message_callback, msg);
      else
        messages->put(msg);

//      return Parser.XML.NSTree.STOP_WALK;
   }
   else if(type=="presence") // we have a presence update.
   {
      mapping a=node->get_attributes();
      if(!a->type) a->type="available";

      foreach(node->get_children(), object n)
         low_parse_presence(n, a);
      if(a->type && a->type=="subscribe")
         handle_subscribe(a->from);
      else if(a->type && a->type=="unsubscribe")
         handle_unsubscribe(a->from);
      else if(a->type && a->type=="subscribed")
         handle_subscribed(a->from);
      else if(a->type && a->type=="unsubscribed")
         handle_unsubscribed(a->from);
          
       WERROR("got presence data from " + sprintf("%O", a) + "\n");
       presence[a->from]=a;
       string bn=((a->from)/"/")[0];
       if(presence_callback)
         call_function(presence_callback, a);
      if(a->type && a->type=="unavailable" && roster[bn])
         roster[bn]->clients-=({a->from});
       else if(roster[bn]) 
          roster[bn]->clients=Array.uniq(roster[bn]->clients + ({a->from}));
   }
   else if(type=="iq") // we have an iq
   {
      mapping a=node->get_attributes();
      low_parse_iq(node, a);
      WERROR("got iq data from " + sprintf("%O", a) + "\n");
  
   } 
   else if((type_registry = get_type_registry(node))) {
      type_registry->handle_message(node, this);
   }
   else 
   {
      WERROR("unknown data from server: " + node->render_xml() +"\n");
   }
}

protected int low_parse_message(object node, mapping msg)
{
    if(node->get_tag_name()=="html")
    {
      msg["html"]=(string)node;
      return 0;
    }
    if(node->get_node_type()==Parser.XML.Tree.XML_TEXT)
      return 0;
    if(node->get_node_type()==Parser.XML.Tree.XML_ELEMENT)
    msg[node->get_tag_name()]=node->value_of_node();

    return 1;
}

protected int low_parse_presence(object node, mapping a)
{  
    if(node[0])
      a[node->get_tag_name()]=node[0]->get_text();
}

protected int low_parse_iq(object node, mapping a)
{

    if(a->type=="result")
    {
       WERROR("received a result for request " + a->id + "\n");
    }
    if(node[0] && node[0]->get_tag_name()=="query")
    {
       WERROR("got a query\n");
       switch(node[0]->get_ns())
       {
         case "xmpp:iq:roster":
           if(a->type=="set")
           {
             WERROR("working with a set roster query\n");
             foreach(node[0]->get_children(), object i)
             {
               if(i->get_tag_name()=="item")
               {
                 mapping ent=i->get_attributes();

                 if(!roster[ent->jid])
                   roster[ent->jid]=([]);
                 roster[ent->jid]->name=(ent->name||"");
                 roster[ent->jid]->subscription=(ent->subscription||"");
                 foreach(i->get_children(), object gp)
                   if(gp->get_tag_name()=="group")
                     roster[ent->jid]->group=gp[0]->get_text();
		if(!roster[ent->jid]->clients)
                   roster[ent->jid]->clients=({});
                if(roster_callback)
                  call_function(roster_callback, roster);
               }
             }
           }
         break;
         default:
           WERROR("unknown iq query type " + node[0]->get_ns() + ".\n");
         break;
       }
    }
    return 1;
}

protected void negotiate_features(array features) {
  array ordered_features = ({});

  // TODO be more sophisticated about this.
  foreach(features;; object feature) {
    string name = feature->get_tag_name();
    if(name == "starttls") ordered_features = ({feature}) + ordered_features;
    else ordered_features += ({feature});
  }
  foreach(ordered_features;; object feature) {
    string name = feature->get_tag_name();
    WERROR("preparing to negotiate " + name + "\n");
    switch(name) {
      case "mechanisms":
        negotiate_mechanisms(feature->get_children());
        return;
        break;
      case "bind":
        bind_resource();
        break;
      case "session": 
        request_session();
        break;
      case "starttls":
        starttls();
        return; // starttls basically starts the whole shebang over.
        break;
      default:
        WERROR("unknown feature " + name + "\n");
    }
  }
  negotiation_complete = 1; // TODO be more sophisticated about knowing when we're actually done.
  set_background_mode(1);
  if(connect_callback) 
     connect_callback(this);
}

int id = 1;
protected string gen_id() {
  return "id" + id++ + time() + "" ;
}

protected void request_session() {
  send_msg("<iq id='sess_" + gen_id() + "' type='set' to='" + server + "'>"
           "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>", 1);

  object r = sync_await_response();

  foreach(r->get_children();; object node) {
    if(node->get_tag_name() == "iq" && node->get_attributes()->type == "result") {
      sessionid = node->get_attributes()->id;
    }
  }

}

protected void bind_resource() {
  send_msg("<iq id='" + gen_id() + "' type='set'>"
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
         "<resource>" + (_client_name||(string)Standards.UUID.make_version4()) + "</resource>"
        "</bind>"
      "</iq>", 1);

  object r = sync_await_response();
  foreach(r->get_children();; object node) {
    if(node->get_tag_name() == "iq" && node->get_attributes()->type == "result") {
      foreach(node->get_children();; object res) {
        if(res->get_tag_name() == "bind") {
          foreach(res->get_children();; object j) {
            if(j->get_tag_name() == "jid") {
              jid = j->value_of_node();
            }
          }
        }
      }
    }
  }

  if(!jid) throw(Error.Generic("bind resource failed.\n"));
  WERROR("JID: " + jid + "\n");
}

protected int(0..1) negotiate_mechanisms(array opts) {
  selected_mechanism = 0;
  multiset valid_mechanisms = (<"PLAIN">);
  foreach(opts;; object opt) {
    if(opt->get_tag_name() != "mechanism") 
      throw(Error.Generic("Expected tag named mechanism, got " + opt->get_tag_name() + "\n"));
    string mechanism = opt->value_of_node();
    WERROR("mechanism: " + mechanism + "\n");
    if(attempted_mechanisms[mechanism]) { 
      WERROR("skipping " + mechanism + "\n"); 
      continue; 
    }
    if(valid_mechanisms[mechanism]) { // TODO primitive... we stop at the first hit.
      selected_mechanism = mechanism;
      attempted_mechanisms[selected_mechanism] = 1;
    }
}
   if(!selected_mechanism) {
     throw(Error.Generic("Unable to agree on an authentication mechanism.\n"));
   }

   if(selected_mechanism == "PLAIN") {
     WERROR("sending PLAIN for password: " + password + "\n");
     send_msg("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='" + selected_mechanism + "'>" +
        MIME.encode_base64("\0" + user + "\0" + password)   + "</auth>", 1);
     object r = sync_await_response();
      array children = r->get_children();
  foreach(children;; object node) {
    if(node->get_tag_name() == "success")
    {
       call_out(begin, 0);
       return 0;	
    }
}
   }
   else
     send_msg("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='" + selected_mechanism + "'/>", 1);

}

protected void starttls() {
  send_msg("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", 1);
  object r = sync_await_response();
  array children = r->get_children();
  foreach(children;; object node) {
    if(node->get_tag_name() == "proceed")
    {
      do_starttls();
      return;
    }
  }
  throw(Error.Generic("Never got proceeed from server for starttls.\n"));
}

protected void handle_unsubscribe(string who)
{
  int res;
  if(unsubscribe_callback)
    res=unsubscribe_callback(who);
  if(res)
    respond_unsubscribed(who);
  else
    respond_subscribed(who);
}

protected void handle_subscribe(string who)
{
  int res;
  if(subscribe_callback)
    res=subscribe_callback(who);
  if(res)
    respond_subscribed(who);
  else
    respond_unsubscribed(who);
}

protected void handle_unsubscribed(string who)
{
  if(unsubscribed_callback)
    unsubscribed_callback(who);

  // acknowledge

  string msg="";
  msg+="<presence type='unsubscribe' to='" + who + "'/>";

  send_msg(msg);
  WERROR("acknowledged subscription.\n");
}

protected void handle_subscribed(string who)
{
  if(subscribed_callback)
    subscribed_callback(who);

  // acknowledge

  string msg="";
  msg+="<presence type='subscribe' to='" + who + "'/>";

  send_msg(msg);
  WERROR("acknowledged subscription.\n");
}

protected void low_write_message(mixed id)
{
	if(!sizeof(write_buf)) return;
    int w = conn->write(write_buf);
    if(w < sizeof(write_buf))
      write_buf = write_buf[w..];
    else write_buf = "";
}

protected void send_msg(string msg, int|void force)
{
  if(!force && !negotiation_complete) throw(Error.Generic("Cannot send message " + msg + " until negotiation is complete.\n"));
  if(is_background)
  {
    write_buf += msg;
    int w = conn->write(write_buf);
    if(w < sizeof(write_buf))
      write_buf = write_buf[w..];
    else write_buf = "";
    WERROR(sprintf("wrote %d, buf size %d\n", w, sizeof(write_buf)));
  }
  else
    conn->write(msg);
  WERROR("sent : " + msg + "\n\n");
}
