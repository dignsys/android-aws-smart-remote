/**
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *    http://aws.amazon.com/apache2.0
 *
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and
 * limitations under the License.
 */

package com.amazonaws.demo.androidpubsub;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.amazonaws.auth.CognitoCachingCredentialsProvider;
import com.amazonaws.mobileconnectors.iot.AWSIotKeystoreHelper;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttClientStatusCallback;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttLastWillAndTestament;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttManager;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttNewMessageCallback;
import com.amazonaws.mobileconnectors.iot.AWSIotMqttQos;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.iot.AWSIotClient;
import com.amazonaws.services.iot.model.AttachPrincipalPolicyRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateRequest;
import com.amazonaws.services.iot.model.CreateKeysAndCertificateResult;

import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.util.UUID;

public class PubSubActivity extends Activity implements View.OnClickListener {

    static final String LOG_TAG = PubSubActivity.class.getCanonicalName();

    // --- Constants to modify per your configuration ---

    // IoT endpoint
    // AWS Iot CLI describe-endpoint call returns: XXXXXXXXXX.iot.<region>.amazonaws.com
    private static final String CUSTOMER_SPECIFIC_ENDPOINT = "<CHANGE_ME>";
    // Cognito pool ID. For this app, pool needs to be unauthenticated pool with
    // AWS IoT permissions.
    private static final String COGNITO_POOL_ID = "<CHANGE_ME>";
    // Name of the AWS IoT policy to attach to a newly created certificate
    private static final String AWS_IOT_POLICY_NAME = "CHANGE_ME";

    // Region of AWS IoT
    private static final Regions MY_REGION = Regions.US_EAST_1;
    // Filename of KeyStore file on the filesystem
    private static final String KEYSTORE_NAME = "iot_keystore";
    // Password for the private key in the KeyStore
    private static final String KEYSTORE_PASSWORD = "password";
    // Certificate and key aliases in the KeyStore
    private static final String CERTIFICATE_ID = "default";

    EditText txtSubcribe;
    EditText txtTopic;
    EditText txtMessage;

    TextView tvLastMessage;
    TextView tvClientId;
    TextView tvStatus;

    Button btnMenuRemoconTV;
    Button btnMenuRemoconVC;
    Button btnMenuSettingTV;
    Button btnMenuSettingVC;
    LinearLayout layoutMenuRemoconTV;
    LinearLayout layoutMenuRemoconVC;
    LinearLayout layoutMenuSetting;

    Button btnConnect;
    Button btnSubscribe;
    Button btnPublish;
    Button btnDisconnect;

    // TV
    Button btnTVPowerOn;
    Button btnTVVolumeUp;
    Button btnTVVolumeDown;
    Button btnTVChannelUp;
    Button btnTVChannelDown;
    //Button btnTVMenuOn;
    //Button btnTVMenuUp;
    //Button btnTVMenuDown;
    //Button btnTVMenuLeft;
    //Button btnTVMenuRight;

    // VC
    Button btnVCStart;
    Button btnVCHome;
    Button btnVCDirUp;
    Button btnVCDirDown;
    Button btnVCDirLeft;
    Button btnVCDirRight;

    AWSIotClient mIotAndroidClient;
    AWSIotMqttManager mqttManager;
    String clientId;
    String keystorePath;
    String keystoreName;
    String keystorePassword;

    KeyStore clientKeyStore = null;
    String certificateId;

    CognitoCachingCredentialsProvider credentialsProvider;

    private static Context context = null;
    String subscribe_token = null;
    String topic_token = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        this.context = getApplicationContext();
        setLayout();

        // MQTT client IDs are required to be unique per AWS IoT account.
        // This UUID is "practically unique" but does not _guarantee_
        // uniqueness.
        clientId = UUID.randomUUID().toString();
        tvClientId.setText(clientId);

        // Initialize the AWS Cognito credentials provider
        credentialsProvider = new CognitoCachingCredentialsProvider(
                getApplicationContext(), // context
                COGNITO_POOL_ID, // Identity Pool ID
                MY_REGION // Region
        );

        Region region = Region.getRegion(MY_REGION);

        // MQTT Client
        mqttManager = new AWSIotMqttManager(clientId, CUSTOMER_SPECIFIC_ENDPOINT);

        // Set keepalive to 10 seconds.  Will recognize disconnects more quickly but will also send
        // MQTT pings every 10 seconds.
        mqttManager.setKeepAlive(10);

        // Set Last Will and Testament for MQTT.  On an unclean disconnect (loss of connection)
        // AWS IoT will publish this message to alert other clients.
        AWSIotMqttLastWillAndTestament lwt = new AWSIotMqttLastWillAndTestament("my/lwt/topic",
                "Android client lost connection", AWSIotMqttQos.QOS0);
        mqttManager.setMqttLastWillAndTestament(lwt);

        // IoT Client (for creation of certificate if needed)
        mIotAndroidClient = new AWSIotClient(credentialsProvider);
        mIotAndroidClient.setRegion(region);

        keystorePath = getFilesDir().getPath();
        keystoreName = KEYSTORE_NAME;
        keystorePassword = KEYSTORE_PASSWORD;
        certificateId = CERTIFICATE_ID;

        // To load cert/key from keystore on filesystem
        try {
            if (AWSIotKeystoreHelper.isKeystorePresent(keystorePath, keystoreName)) {
                if (AWSIotKeystoreHelper.keystoreContainsAlias(certificateId, keystorePath,
                        keystoreName, keystorePassword)) {
                    Log.i(LOG_TAG, "Certificate " + certificateId
                            + " found in keystore - using for MQTT.");
                    // load keystore from file into memory to pass on connection
                    clientKeyStore = AWSIotKeystoreHelper.getIotKeystore(certificateId,
                            keystorePath, keystoreName, keystorePassword);
                    btnConnect.setEnabled(true);
                } else {
                    Log.i(LOG_TAG, "Key/cert " + certificateId + " not found in keystore.");
                }
            } else {
                Log.i(LOG_TAG, "Keystore " + keystorePath + "/" + keystoreName + " not found.");
            }
        } catch (Exception e) {
            Log.e(LOG_TAG, "An error occurred retrieving cert/key from keystore.", e);
        }

        if (clientKeyStore == null) {
            Log.i(LOG_TAG, "Cert/key was not found in keystore - creating new key and certificate.");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        // Create a new private key and certificate. This call
                        // creates both on the server and returns them to the
                        // device.
                        CreateKeysAndCertificateRequest createKeysAndCertificateRequest =
                                new CreateKeysAndCertificateRequest();
                        createKeysAndCertificateRequest.setSetAsActive(true);
                        final CreateKeysAndCertificateResult createKeysAndCertificateResult;
                        createKeysAndCertificateResult =
                                mIotAndroidClient.createKeysAndCertificate(createKeysAndCertificateRequest);
                        Log.i(LOG_TAG,
                                "Cert ID: " +
                                        createKeysAndCertificateResult.getCertificateId() +
                                        " created.");

                        // store in keystore for use in MQTT client
                        // saved as alias "default" so a new certificate isn't
                        // generated each run of this application
                        AWSIotKeystoreHelper.saveCertificateAndPrivateKey(certificateId,
                                createKeysAndCertificateResult.getCertificatePem(),
                                createKeysAndCertificateResult.getKeyPair().getPrivateKey(),
                                keystorePath, keystoreName, keystorePassword);

                        // load keystore from file into memory to pass on
                        // connection
                        clientKeyStore = AWSIotKeystoreHelper.getIotKeystore(certificateId,
                                keystorePath, keystoreName, keystorePassword);

                        // Attach a policy to the newly created certificate.
                        // This flow assumes the policy was already created in
                        // AWS IoT and we are now just attaching it to the
                        // certificate.
                        AttachPrincipalPolicyRequest policyAttachRequest =
                                new AttachPrincipalPolicyRequest();
                        policyAttachRequest.setPolicyName(AWS_IOT_POLICY_NAME);
                        policyAttachRequest.setPrincipal(createKeysAndCertificateResult
                                .getCertificateArn());
                        mIotAndroidClient.attachPrincipalPolicy(policyAttachRequest);

                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                btnConnect.setEnabled(true);
                            }
                        });
                    } catch (Exception e) {
                        Log.e(LOG_TAG,
                                "Exception occurred when generating new private key and certificate.",
                                e);
                    }
                }
            }).start();
        }

        btnConnect.callOnClick();
    }

    private void setLayout() {
        // Sets up UI references.
        btnMenuRemoconTV = (Button) findViewById(R.id.btnMenuRemoconTV);
        btnMenuRemoconTV.setOnClickListener(this);
        btnMenuRemoconVC = (Button) findViewById(R.id.btnMenuRemoconVC);
        btnMenuRemoconVC.setOnClickListener(this);
        btnMenuSettingTV = (Button) findViewById(R.id.btnMenuSettingTV);
        btnMenuSettingTV.setOnClickListener(this);
        btnMenuSettingVC = (Button) findViewById(R.id.btnMenuSettingVC);
        btnMenuSettingVC.setOnClickListener(this);

        layoutMenuRemoconTV = (LinearLayout) findViewById(R.id.layoutMenuRemoconTV);
        layoutMenuRemoconVC = (LinearLayout) findViewById(R.id.layoutMenuRemoconVC);
        layoutMenuSetting = (LinearLayout) findViewById(R.id.layoutMenuSetting);

        txtSubcribe = (EditText) findViewById(R.id.txtSubcribe);
        txtTopic = (EditText) findViewById(R.id.txtTopic);
        txtMessage = (EditText) findViewById(R.id.txtMessage);

        tvLastMessage = (TextView) findViewById(R.id.tvLastMessage);
        tvClientId = (TextView) findViewById(R.id.tvClientId);
        tvStatus = (TextView) findViewById(R.id.tvStatus);

        btnConnect = (Button) findViewById(R.id.btnConnect);
        btnConnect.setOnClickListener(connectClick);
        btnConnect.setEnabled(false);

        btnSubscribe = (Button) findViewById(R.id.btnSubscribe);
        btnSubscribe.setOnClickListener(subscribeClick);

        btnPublish = (Button) findViewById(R.id.btnPublish);
        btnPublish.setOnClickListener(publishClick);

        btnDisconnect = (Button) findViewById(R.id.btnDisconnect);
        btnDisconnect.setOnClickListener(disconnectClick);

        // tv remocon-key command
        btnTVPowerOn = (Button) findViewById(R.id.btnTVPowerOn);
        btnTVPowerOn.setOnClickListener(this);
        btnTVVolumeUp = (Button) findViewById(R.id.btnTVVolumeUp);
        btnTVVolumeUp.setOnClickListener(this);
        btnTVVolumeDown = (Button) findViewById(R.id.btnTVVolumeDown);
        btnTVVolumeDown.setOnClickListener(this);
        btnTVChannelUp = (Button) findViewById(R.id.btnTVChannelUp);
        btnTVChannelUp.setOnClickListener(this);
        btnTVChannelDown = (Button) findViewById(R.id.btnTVChannelDown);
        btnTVChannelDown.setOnClickListener(this);

        /*
        btnTVMenuOn = (Button) findViewById(R.id.btnTVMenuOn);
        btnTVMenuOn.setOnClickListener(this);
        btnTVMenuUp = (Button) findViewById(R.id.btnTVMenuUp);
        btnTVMenuUp.setOnClickListener(this);
        btnTVMenuDown = (Button) findViewById(R.id.btnTVMenuDown);
        btnTVMenuDown.setOnClickListener(this);
        btnTVMenuLeft = (Button) findViewById(R.id.btnTVMenuLeft);
        btnTVMenuLeft.setOnClickListener(this);
        btnTVMenuRight = (Button) findViewById(R.id.btnTVMenuRight);
        btnTVMenuRight.setOnClickListener(this);
        */

        // vc remocon-key command
        btnVCStart = (Button) findViewById(R.id.btnVCStart);
        btnVCStart.setOnClickListener(this);
        btnVCHome = (Button) findViewById(R.id.btnVCHome);
        btnVCHome.setOnClickListener(this);
        btnVCDirDown = (Button) findViewById(R.id.btnVCDirDown);
        btnVCDirDown.setOnClickListener(this);
        btnVCDirUp = (Button) findViewById(R.id.btnVCDirUp);
        btnVCDirUp.setOnClickListener(this);
        btnVCDirLeft = (Button) findViewById(R.id.btnVCDirLeft);
        btnVCDirLeft.setOnClickListener(this);
        btnVCDirRight = (Button) findViewById(R.id.btnVCDirRight);
        btnVCDirRight.setOnClickListener(this);

        subscribe_token = SettingData.getSharedPreferenceString(context, SettingData.PREF_AWS_SUBSCRIBE_TOKEN);
        topic_token = SettingData.getSharedPreferenceString(context, SettingData.PREF_AWS_TOPIC_TOKEN);
        if (subscribe_token == "") {
            subscribe_token = SettingData.DEFAULT_AWS_SUBSCRIBE_NAME;
        }
        if (topic_token == "") {
            topic_token = SettingData.DEFAULT_AWS_TOPIC_NAME;
        }
        txtSubcribe.setText(subscribe_token);
        txtTopic.setText(topic_token);
    }

    @Override
    public void onClick(View v) {

        final String topic = txtTopic.getText().toString();
        String msg = null;

        switch(v.getId()) {
            case R.id.btnMenuRemoconTV:
                layoutMenuRemoconTV.setVisibility(View.VISIBLE);
                layoutMenuRemoconVC.setVisibility(View.GONE);
                layoutMenuSetting.setVisibility(View.GONE);
                btnMenuRemoconTV.setBackgroundResource(R.drawable.menu_tv_active);
                btnMenuRemoconVC.setBackgroundResource(R.drawable.menu_vaccum_normal);
                btnMenuSettingTV.setBackgroundResource(R.drawable.shape_gray_default);
                break;
            case R.id.btnMenuRemoconVC:
                layoutMenuRemoconTV.setVisibility(View.GONE);
                layoutMenuRemoconVC.setVisibility(View.VISIBLE);
                layoutMenuSetting.setVisibility(View.GONE);
                btnMenuRemoconTV.setBackgroundResource(R.drawable.menu_tv_normal);
                btnMenuRemoconVC.setBackgroundResource(R.drawable.menu_vaccum_active);
                btnMenuSettingVC.setBackgroundResource(R.drawable.shape_gray_default);
                break;
            case R.id.btnMenuSettingTV:
            case R.id.btnMenuSettingVC:
                layoutMenuRemoconTV.setVisibility(View.GONE);
                layoutMenuRemoconVC.setVisibility(View.GONE);
                layoutMenuSetting.setVisibility(View.VISIBLE);
                btnMenuRemoconTV.setBackgroundResource(R.drawable.menu_tv_normal);
                btnMenuRemoconVC.setBackgroundResource(R.drawable.menu_vaccum_normal);
                //btnMenuSettingTV.setBackgroundResource(R.drawable.shape_gray_default);
                break;

            case R.id.btnTVPowerOn:
                msg = getResources().getString(R.string.message_tv_power_on);
                break;
            case R.id.btnTVVolumeUp:
                msg = getResources().getString(R.string.message_tv_volume_up);
                break;
            case R.id.btnTVVolumeDown:
                msg = getResources().getString(R.string.message_tv_volume_down);
                break;
            case R.id.btnTVChannelUp:
                msg = getResources().getString(R.string.message_tv_channel_up);
                break;
            case R.id.btnTVChannelDown:
                msg = getResources().getString(R.string.message_tv_channel_down);
                break;
            /*
            case R.id.btnTVMenuOn:
                msg = getResources().getString(R.string.message_tv_menu_on);
                break;
            case R.id.btnTVMenuUp:
                msg = getResources().getString(R.string.message_tv_menu_up);
                break;
            case R.id.btnTVMenuDown:
                msg = getResources().getString(R.string.message_tv_menu_down);
                break;
            case R.id.btnTVMenuLeft:
                msg = getResources().getString(R.string.message_tv_menu_left);
                break;
            case R.id.btnTVMenuRight:
                msg = getResources().getString(R.string.message_tv_menu_right);
                break;
                */

            case R.id.btnVCStart:
                msg = getResources().getString(R.string.message_vc_start);
                break;
            case R.id.btnVCHome:
                msg = getResources().getString(R.string.message_vc_home);
                break;
            case R.id.btnVCDirUp:
                msg = getResources().getString(R.string.message_vc_up);
                break;
            case R.id.btnVCDirDown:
                msg = getResources().getString(R.string.message_vc_down);
                break;
            case R.id.btnVCDirRight:
                msg = getResources().getString(R.string.message_vc_right);
                break;
            case R.id.btnVCDirLeft:
                msg = getResources().getString(R.string.message_vc_left);
                break;
        }
        if (msg != null) {
            try {
                mqttManager.publishString(msg, topic, AWSIotMqttQos.QOS0);
                tvLastMessage.setText(msg);
            } catch (Exception e) {
                Log.e(LOG_TAG, "Message send error.", e);
            }
        }
    }

    View.OnClickListener connectClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            Log.d(LOG_TAG, "clientId = " + clientId);

            try {
                mqttManager.connect(clientKeyStore, new AWSIotMqttClientStatusCallback() {
                    @Override
                    public void onStatusChanged(final AWSIotMqttClientStatus status,
                            final Throwable throwable) {
                        Log.d(LOG_TAG, "Status = " + String.valueOf(status));

                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                if (status == AWSIotMqttClientStatus.Connecting) {
                                    tvStatus.setText("Connecting...");

                                } else if (status == AWSIotMqttClientStatus.Connected) {
                                    tvStatus.setText("Connected");

                                } else if (status == AWSIotMqttClientStatus.Reconnecting) {
                                    if (throwable != null) {
                                        Log.e(LOG_TAG, "Connection error.", throwable);
                                    }
                                    tvStatus.setText("Reconnecting");
                                } else if (status == AWSIotMqttClientStatus.ConnectionLost) {
                                    if (throwable != null) {
                                        Log.e(LOG_TAG, "Connection error.", throwable);
                                    }
                                    tvStatus.setText("Disconnected");
                                } else {
                                    tvStatus.setText("Disconnected");

                                }
                            }
                        });
                    }
                });
            } catch (final Exception e) {
                Log.e(LOG_TAG, "Connection error.", e);
                tvStatus.setText("Error! " + e.getMessage());
            }
        }
    };

    View.OnClickListener subscribeClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            final String topic = txtSubcribe.getText().toString();

            Log.d(LOG_TAG, "topic = " + topic);

            try {
                mqttManager.subscribeToTopic(topic, AWSIotMqttQos.QOS0,
                        new AWSIotMqttNewMessageCallback() {
                            @Override
                            public void onMessageArrived(final String topic, final byte[] data) {
                                runOnUiThread(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            String message = new String(data, "UTF-8");
                                            Log.d(LOG_TAG, "Message arrived:");
                                            Log.d(LOG_TAG, "   Topic: " + topic);
                                            Log.d(LOG_TAG, " Message: " + message);

                                            tvLastMessage.setText(message);

                                        } catch (UnsupportedEncodingException e) {
                                            Log.e(LOG_TAG, "Message encoding error.", e);
                                        }
                                    }
                                });
                            }
                        });
                if (subscribe_token.equals(topic) == false) {
                    subscribe_token = topic;
                    SettingData.setSharedPreferenceString(context, SettingData.PREF_AWS_SUBSCRIBE_TOKEN, subscribe_token);
                }
            } catch (Exception e) {
                Log.e(LOG_TAG, "Subscription error.", e);
            }
        }
    };

    View.OnClickListener publishClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            final String topic = txtTopic.getText().toString();
            final String msg = txtMessage.getText().toString();

            try {
                mqttManager.publishString(msg, topic, AWSIotMqttQos.QOS0);
                if (topic_token.equals(topic) == false) {
                    topic_token = topic;
                    SettingData.setSharedPreferenceString(context, SettingData.PREF_AWS_TOPIC_TOKEN, topic_token);
                }
            } catch (Exception e) {
                Log.e(LOG_TAG, "Publish error.", e);
            }

        }
    };

    View.OnClickListener disconnectClick = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            try {
                mqttManager.disconnect();
            } catch (Exception e) {
                Log.e(LOG_TAG, "Disconnect error.", e);
            }

        }
    };
}
