package com.anonpass.anondroid;

import java.io.UnsupportedEncodingException;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;

import android.os.Bundle;
import android.app.Activity;
import android.graphics.Bitmap;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.util.Log;
import android.util.Base64;
import android.widget.LinearLayout;

import com.anonpass.anondroid.PBCNative;

public class AnondroidMain extends Activity {
	private final BarcodeFormat format = BarcodeFormat.QR_CODE;
	private static final int WHITE = 0xFFFFFFFF;
	private static final int BLACK = 0xFF000000;
    private Button button1;
	  
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_anondroid_main);
        
        button1 = (Button) findViewById(R.id.button1);
        button1.setOnClickListener(new View.OnClickListener() {
			
			public void onClick(View v) {
                Button button = (Button)v;
				String contentsToEncode;
				final ImageView qrpanel = (ImageView) findViewById(R.id.imageView1);
				int	dimension = 50; 
				MultiFormatWriter writer = new MultiFormatWriter();

                long start_time = System.nanoTime(),
                    end_time;
                byte[] buf = (new PBCNative()).encrypt();
                end_time = System.nanoTime();

                String strtime = String.format("%f usecs", (end_time - start_time)/1000.0);
                button.setText("Please scan this code");
                Log.v("Anondroid", strtime);
                
                // WHY ISO-8859-1?
                // http://stackoverflow.com/questions/2489048/qr-code-encoding-and-decoding-using-zxing
                contentsToEncode = Base64.encodeToString(buf, Base64.NO_WRAP|Base64.NO_PADDING);
                Log.v("Anondroid", "after encrypt buf size: " + contentsToEncode.length());

				try {
					BitMatrix result = writer.encode(contentsToEncode, format, dimension, dimension, null);
					int width = result.getWidth();
				    int height = result.getHeight();
                    int mag_ratio = 3;
                    Log.v("Anondroid", "width: " + width + ", height: " + height);
                    
				    int[] pixels = new int[width * height * mag_ratio * mag_ratio];
				    for (int y = 0; y < height * mag_ratio; y++) {
				      int offset = y * width * mag_ratio;
				      for (int x = 0; x < width * mag_ratio; x++) {
				        pixels[offset + x] = result.get(x/mag_ratio, y/mag_ratio) ? BLACK : WHITE;
				      }
				    }
				    Bitmap bitmap = Bitmap.createBitmap(width*mag_ratio, height*mag_ratio, Bitmap.Config.ARGB_8888);
				    bitmap.setPixels(pixels, 0, width*mag_ratio, 0, 0, width*mag_ratio, height*mag_ratio);

				    qrpanel.setImageBitmap(bitmap);
                    
                    // LinearLayout.LayoutParams lp = new LinearLayout.LayoutoParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, height*mag_ratio));
                    // qrpanel.setLayoutParams(lp);
                    // qrpanel.getLayoutParams().height = height*mag_ratio;
                    // qrpanel.getLayoutParams().width = width*mag_ratio;
				    
				} catch (WriterException e) {
					e.printStackTrace();
				}
			}
		});

        Log.v("Anondroid", "onCreate");
    }

    @Override
    public void onStart() {
        super.onStart();
        button1.performClick();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_anondroid_main, menu);
        return true;
    }
}
