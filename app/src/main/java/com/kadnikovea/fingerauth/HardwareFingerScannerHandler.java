package com.kadnikovea.fingerauth;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.widget.Toast;

import javax.crypto.Cipher;

import static android.content.Context.KEYGUARD_SERVICE;



//TODO make builder pattern
@RequiresApi(api = Build.VERSION_CODES.M)
public class HardwareFingerScannerHandler {

    private Context context;
    private Cipher cipher;
    private FingerprintManager fingerprintManager;
    private CancellationSignal cancellationSignal;
    private IonHardwareScannerResult listener;

    public static void create(Context context, Cipher cipher, IonHardwareScannerResult listener){
        new HardwareFingerScannerHandler(context, cipher, listener).handle();
    }

    private HardwareFingerScannerHandler(Context context, Cipher cipher, IonHardwareScannerResult listener) {
        this.context = context;
        this.cipher = cipher;
        this.listener = listener;
        this.fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void handle(){
        switch (checkSensorState(this.context)){

            case NOT_SUPPORTED:
//                нет встроенного сканера
                Toast.makeText(context, "Your device doesn't support fingerprint authentication", Toast.LENGTH_LONG).show();
                break;
            case NO_FINGERPRINTS:
//                нет откатанных пальцев (возможно отправить в настройки, объяснить как)
                Toast.makeText(
                        context,
                        "No fingerprint configured. Please register at least one fingerprint in your device's Settings",
                        Toast.LENGTH_LONG).show();
                break;
            case NOT_BLOCKED:
//                обязательно должен быть включен режим Lock Screen  (пароль или паттерн, возможно с отпечатком)
                Toast.makeText(
                        context,
                        "Please enable lock screen security in your device's Settings",
                        Toast.LENGTH_LONG).show();
                break;
            case PERMISSION_DENIED:
                Toast.makeText(context, "Please enable the fingerprint permission", Toast.LENGTH_LONG).show();
                break;
            case READY:
//                готово
//                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M && android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
                    //api 23-27

                Drawable icon = context.getDrawable(R.drawable.ic_fingerprint);
                icon.setColorFilter(Color.BLUE, PorterDuff.Mode.SRC_IN);

                AlertDialog alertDialog = new AlertDialog.Builder(context).create();
                alertDialog.setTitle("Sign in");
                alertDialog.setMessage("Confirm fingerprint to continue");
                alertDialog.setIcon(icon);
                alertDialog.setButton(AlertDialog.BUTTON_NEGATIVE, context.getText(android.R.string.cancel),
                        new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                stopListeningAuthentication();
                                dialog.dismiss();
                            }
                        });

                alertDialog.show();

//                FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);


                    cancellationSignal = new CancellationSignal();

                    fingerprintManager.authenticate(new FingerprintManager.CryptoObject(cipher),
                            cancellationSignal,
                            0,
                            new FingerprintManager.AuthenticationCallback() {
                                @Override
                                public void onAuthenticationError(int errorCode, CharSequence errString) {
                                    super.onAuthenticationError(errorCode, errString);
                                    Toast.makeText(context, "onAuthenticationError", Toast.LENGTH_LONG).show();
                                }

                                @Override
                                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                    super.onAuthenticationHelp(helpCode, helpString);
                                    Toast.makeText(context, "onAuthenticationHelp", Toast.LENGTH_LONG).show();
                                }

                                @Override
                                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                    super.onAuthenticationSucceeded(result);
                                    Toast.makeText(context, "onAuthenticationSucceeded", Toast.LENGTH_LONG).show();

//                                    do Your nasty work
                                    listener.onHardwareScannerSuccess();
                                    alertDialog.dismiss();

                                }

                                @Override
                                public void onAuthenticationFailed() {
                                    super.onAuthenticationFailed();
                                    Toast.makeText(context, "onAuthenticationFailed", Toast.LENGTH_LONG).show();
                                }
                            }
                            ,
                            null);

//                }else if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ){
//                    //api higher 28
//
////                    Biometric smth
//
//                }


                Toast.makeText(context, "Scanner READY", Toast.LENGTH_LONG).show();
                break;
            default:
                Toast.makeText(context, "Unknown Fingerprint scanner Error", Toast.LENGTH_LONG).show();
                break;
        }
    }

    private void stopListeningAuthentication() {
        if (cancellationSignal != null) {
            cancellationSignal.cancel();
            cancellationSignal = null;
            cleanHandler();
        }

    }

    private void cleanHandler() {
       context = null;
       cipher = null;
       fingerprintManager = null;
       cancellationSignal = null;
       listener = null;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private SensorState checkSensorState(@NonNull Context context) {

        KeyguardManager keyguardManager =
                (KeyguardManager) context.getSystemService(KEYGUARD_SERVICE);
        // doesn work on some xiaomi
        //        FingerprintManagerCompat fingerprintManager = FingerprintManagerCompat.from(context);
        //        FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);


        if(!checkFingerprintCompatibility(context)){
            return SensorState.NOT_SUPPORTED;
        }else  if(context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED){
            return SensorState.PERMISSION_DENIED;

        }else if(!fingerprintManager.hasEnrolledFingerprints()){
            return SensorState.NO_FINGERPRINTS;
        } else if (!keyguardManager.isKeyguardSecure()) {
            return SensorState.NOT_BLOCKED;
        }
        return SensorState.READY;

    }

    private boolean checkFingerprintCompatibility(@NonNull Context context) {
        // doesn work on some xiaomi
//        return FingerprintManagerCompat.from(context).isHardwareDetected();
        FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(Context.FINGERPRINT_SERVICE);

        return fingerprintManager.isHardwareDetected();
    }

    private enum SensorState {
        NOT_SUPPORTED,
        NOT_BLOCKED, // если устройство не защищено пином, рисунком или паролем
        NO_FINGERPRINTS, // если на устройстве нет отпечатков
        READY,
        PERMISSION_DENIED
    }

    public interface IonHardwareScannerResult{
        void onHardwareScannerSuccess();
    }


}
