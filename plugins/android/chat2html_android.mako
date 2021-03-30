<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>WhatsApp chat</title>
    <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Open+Sans" />
    <style>
    /* message content */
    .content {
      display: inline-block;
      vertical-align: middle;
      text-align: left;
      font-family: sans-serif;
      margin: 0.5em;
    }
    .sent .content {
      float: left;
      text-align: left;
      width: 80%;
    }
    .received .content {
      float: right;
      text-align: right;
      width: 80%;
    }


    /* message metadata */
    /* .received .metadata {
      font-family: monospace;
      font-size: 0.75em; 
      float: left;
      text-align: left;
      width: 20%;
      background-color: white;
    }
    .sent .metadata {
      font-family: monospace;
      font-size: 0.75em;
      float: right;
      text-align: right;
      width: 20%;
      background-color: white;
    } */
    .metadata {
      display: grid;
      background-color: white;
      border-bottom: 1px solid #aaa;
      grid-template-columns: auto auto auto auto auto;
      font-family: monospace;
      font-size: 0.75em;
      margin: 0;
    }

    /* Chat containers */
    .message {
      margin: 0.5em 0;
    }
    /* Received and sent chat container */
    .received {
      border: 1px solid #007780;
      background-color: #27bae166;
      margin-left: 0;
      margin-right: auto;
      width: 90%;
    }
    .sent {
      border: 1px solid #005419;
      background-color: #9cfb6ab3;
      margin-left: auto;
      margin-right: 0;
      width: 90%;
    }

    /* Clear floats */
    .message::after {
      content: "";
      clear: both;
      display: table;
    }

    img {
      /* width: "pixels"; */
      width: auto;
      height : auto;
      max-width: 100%;
      max-height: 95%;
    }
    </style>
  </head>
  <body>
    <% num = 0 %>
    % for r in data:
      <% num = num + 1 %>
      % if r["message_from"] not in ("Terminal", "ME"):
        ## received message
        <div class="message received">
          <div class="metadata">
            ${num}
            <div class="identifier">${r["message_id"]}</div>
            <div class="type">Recibido</div>
            <div class="author">${r["message_from"]}</div>
            <div class="date">${r["date_creation"]}</div>
          </div>
          <div class="content">
            % if r["message_type"] in ["Text message", "Contact"]:
              ${r["message"]}
            % elif r["message_type"] == "Image":
              <img src="${r['message_media_location']}">
            % elif r["message_type"] in ["Video", "Voice/Audio note"]:
              <a href="${r['message_media_location']}">${r["message_media_location"]}</a>
            % elif r["message_type"] == "Location":
              ${r["message"]}: ${r["lon_lat"]}
            % elif r["message_type"] == "Url":
              <% url = 'http' + r["message"].split('http')[-1] %>
              <% url_title = r["message"].split('http')[0] %>
              ${url_title}<a href="${url}">${url}</a>
            % elif r["message_type"] == "Document":
              <a href="${r['message_media_location']}">${r["message"]}</a>
            % elif r["message_type"] == "Deleted":
              This message has been deleted
            % endif
          </div>
        </div>
      % else:
        ## sent message
        <div class="message sent">
          <div class="metadata">
            ${num}
            <div class="identifier">${r["message_id"]}</div>
            <div class="type">Enviado</div>
            <div class="author">${r["message_from"]}</div>
            % if r["date_sent"] is not None:
            <div class="date">${r["date_sent"]}</div>
            % endif
          </div>
          <div class="content">
            % if r["message_type"] in ["Text message", "Contact"]:
              ${r["message"]}
            % elif r["message_type"] == "Image":
              <img src="${r['message_media_location']}">
            % elif r["message_type"] in ["Video", "Voice/Audio note"]:
              <a href="${r['message_media_location']}">${r["message_media_location"]}</a>
            % elif r["message_type"] == "Location":
              ${r["message"]}: ${r["lon_lat"]}
            % elif r["message_type"] == "Url":
              <% url = 'http' + r["message"].split('http')[-1] %>
              <% url_title = r["message"].split('http')[0] %>
              ${url_title}<a href="${url}">${url}</a>
            % elif r["message_type"] == "Document":
              <a href="${r['message_media_location']}">${r["message"]}</a>
            % elif r["message_type"] == "Deleted":
              This message has been deleted
            % endif
          </div>
        </div>
      % endif
    % endfor
  </body>
</html>
